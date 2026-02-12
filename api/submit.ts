import { Resend } from "resend";
import crypto from "crypto";
import fs from "fs";
import path from "path";
import ejs from "ejs";

export const config = {
  api: {
    bodyParser: false, // IMPORTANT for signature verification
  },
};

const resend = new Resend(process.env.RESEND_API_KEY);

// Read raw request body as Buffer
function getRawBody(req: any): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function isFramerSignatureValid(
  secret: string,
  submissionId: string,
  payload: Buffer,
  signature: string
) {
  // Framer signature format: "sha256=<hex>" (71 chars total)
  if (!signature || signature.length !== 71 || !signature.startsWith("sha256=")) {
    return false;
  }

  const hmac = crypto.createHmac("sha256", secret);
  hmac.update(payload);
  hmac.update(submissionId);

  const expected = "sha256=" + hmac.digest("hex");

  // timing-safe compare
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

export default async function handler(req: any, res: any) {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  try {
    const rawBody = await getRawBody(req);

    const framerSecret = process.env.FRAMER_WEBHOOK_SECRET || "";
    const devSecret = process.env.API_SECRET || "";

    // ✅ Dev bypass for Postman (you control this header)
    const devBypass = req.headers["x-dev-bypass"];

    if (devBypass === devSecret) {
      console.log("Dev bypass used");
    } else {
      // ✅ Framer uses these headers (Node lowercases them)
      const signature = req.headers["framer-signature"];
      const submissionId = req.headers["framer-webhook-submission-id"];

      if (!framerSecret || !signature || !submissionId) {
        return res.status(401).json({ error: "Unauthorized" });
      }

      const ok = isFramerSignatureValid(
        framerSecret,
        String(submissionId),
        rawBody,
        String(signature)
      );

      if (!ok) {
        return res.status(401).json({ error: "Invalid signature" });
      }
    }

    // Parse body AFTER verification
    const formData = JSON.parse(rawBody.toString("utf-8"));

    const registration = formData.registration;
    if (!registration) {
      return res.status(400).json({ error: "Registration is required" });
    }

    const cleanedReg = String(registration).replace(/\s+/g, "").toUpperCase();

    // DVLA lookup (optional but requested)
    let dvla: any = null;
    try {
      const dvlaResp = await fetch(
        "https://driver-vehicle-licensing.api.gov.uk/vehicle-enquiry/v1/vehicles",
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "x-api-key": process.env.DVLA_API_KEY || "",
          },
          body: JSON.stringify({ registrationNumber: cleanedReg }),
        }
      );

      if (dvlaResp.ok) {
        dvla = await dvlaResp.json();
      } else {
        console.error("DVLA API failed:", dvlaResp.status, await dvlaResp.text());
      }
    } catch (err) {
      console.error("DVLA error:", err);
    }

    // Render email
    const template = fs.readFileSync(
      path.join(process.cwd(), "templates/email.ejs"),
      "utf-8"
    );

    const html = ejs.render(template, { formData, dvla });

    await resend.emails.send({
      from: "onboarding@resend.dev",
      to: "arshadsaad1998@gmail.com",
      subject: `New Sell Car Submission – ${cleanedReg}`,
      html,
    });

    return res.status(200).json({ success: true });
  } catch (error) {
    console.error("Server error:", error);
    return res.status(500).json({ error: "Internal Server Error" });
  }
}

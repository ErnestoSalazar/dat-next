import nodemailer from 'nodemailer';
import fs from 'fs';
import path from 'path';

// Create transporter
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.gmail.com',
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  }
});

// Template directory
const TEMPLATE_DIR = path.join(process.cwd(), 'lib', 'email-templates');

interface EmailOptions {
  to: string;
  subject: string;
  template: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  variables: Record<string, any>
}

export async function sendEmail(options: EmailOptions) {
  try {
    const templatePath = path.join(TEMPLATE_DIR, `${options.template}.html`);
    
    if (!fs.existsSync(templatePath)) {
      throw new Error(`Email template '${options.template}' not found at ${templatePath}`);
    }
    let templateContent = fs.readFileSync(templatePath, 'utf-8');

    const allVariables = {
      ...options.variables,
      currentYear: new Date().getFullYear(),
    };

    // Replace variables in template
    for (const [key, value] of Object.entries(allVariables)) {
      const placeholder = new RegExp(`{{${key}}}`, 'g');
      templateContent = templateContent.replace(placeholder, String(value));
    }

    const mailOptions = {
      from: process.env.SMTP_FROM,
      to: options.to,
      subject: options.subject,
      html: templateContent,
    }
    
    await transporter.sendMail(mailOptions);
    console.log(`Email sent successfully to ${options.to}`);
  } catch (error) {
    console.error('Filed to send email:', error);
    throw error;
  }
}

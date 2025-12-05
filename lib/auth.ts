// Import functions for creating and verifying JWT tokens
import { jwtVerify, SignJWT } from 'jose';
import { NextRequest } from 'next/server';

const secretKey = process.env.JWT_SECRET;
const key = new TextEncoder().encode(secretKey);


/**
 * CREATE (Encrypt) JWT Token
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function encrypt(payload: any) {
  return await new SignJWT(payload)
  .setProtectedHeader({ alg: 'HS256' }) // Algorithm used to sign the token
  .setIssuedAt()                        // Add issuedd time (iat)
  .setExpirationTime('72h')             // Rokwn Expires in 72 hours
  .sign(key);                           // Sign the token with our secret key
}

/**
 * VERIFY (Decrypt) JWT Token
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function decrypt(input: string): Promise<any> {
  const { payload } = await jwtVerify(input, key, {
    algorithms: ['HS256'],
  });
  return payload;
}

// Create a new session and store it in a cookie
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export async function createSession(user: any) {
  // Set cookie expiration time (72 hours)
  const expires = new Date(Date.now() + 72 * 60 * 60 * 1000);

  // Encryp user info into a JWT
  const sessionToken = await encrypt({ user, expires });

  // Access Next.js cookie API
  const { cookies } = await import('next/headers');
  const cookieStore = await cookies();

  // Save the token in a secure cookie
  cookieStore.set('session', sessionToken, {
    expires,
    httpOnly: true,                                 // Not accessible from JS (more scure)
    secure: process.env.NODE_ENV === 'production',  // Only HTTPS in prod
    sameSite: 'lax',
    path: '/',
  });
}

// Get session for server components or API routes
export async function getSession() {
  // Use Next.js headers API to access cookies
  const { cookies } = await import('next/headers');
  const cookieStore = await cookies();

  const session = cookieStore.get('session')?.value;
  if (!session) return null;

  try {
    return await decrypt(session);
  } catch (error) {
    return null;
  }
}

// Delete session cookie (log out user)
export async function deleteSession() {
  const { cookies } = await import('next/headers');
  const cookieStore = await cookies();

  cookieStore.delete('session');
}

// Get user session from cookies (Middleware use)
export async function getSessionFromRequest(request: NextRequest) {
  const cookieHeader = request.headers.get('cookie');
  if (!cookieHeader) return null;

  const cookies = parseCookies(cookieHeader);
  const session = cookies.session;

  if (!session) return null;

  try {
    return await decrypt(session);
  } catch (error) {
    return null;
  }
}

function parseCookies(cookieHeader: string): Record<string, string> {
  const cookies: Record<string, string> = {};

  // split all cookies by ';' and then each cookie into name=value
  cookieHeader.split(';').forEach((cookie) => {
    const [name, ...valueParts] = cookie.trim().split('=');
    if (name) {
      cookies[name] = valueParts.join('=') // Handle values containing '='
    }
  });

  return cookies;
}

import bcrypt from 'bcryptjs';

const DUMMY_BCRYPT_HASH = '$2b$12$4zylA.9P5A24CYM5G3fSPeUq4byQj0kM8g5mnWfVi2J4M6I7PX9sW';

function parseLoginBody(body) {
  const username = String(body?.username || '').trim();
  const password = String(body?.password || '');
  return { username, password };
}

export async function authRoutes(fastify) {
  fastify.post(
    '/auth/login',
    {
      config: {
        rateLimit: {
          max: fastify.env.AUTH_LOGIN_MAX_ATTEMPTS,
          timeWindow: fastify.env.AUTH_LOGIN_WINDOW
        }
      }
    },
    async (request, reply) => {
      const { username, password } = parseLoginBody(request.body);
      if (!username || !password) {
        return reply.code(400).send({ message: 'Credenciais invalidas' });
      }

      const expectedUsername = fastify.env.AUTH_USERNAME;
      const usernameMatches = username === expectedUsername;
      const hashToCompare = usernameMatches ? fastify.env.AUTH_PASSWORD_HASH : DUMMY_BCRYPT_HASH;
      const passwordMatches = await bcrypt.compare(password, hashToCompare);

      if (!usernameMatches || !passwordMatches) {
        return reply.code(401).send({ message: 'Usuario ou senha invalidos' });
      }

      const token = await reply.jwtSign(
        { sub: username, role: 'admin' },
        { expiresIn: fastify.env.AUTH_TOKEN_TTL }
      );

      return {
        access_token: token,
        token_type: 'bearer',
        role: 'admin'
      };
    }
  );

  fastify.get('/auth/me', { preHandler: [fastify.authenticate] }, async (request) => {
    return {
      username: request.user?.sub || fastify.env.AUTH_USERNAME,
      role: request.user?.role || 'admin'
    };
  });
}
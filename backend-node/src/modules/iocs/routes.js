export async function iocRoutes(fastify) {
  fastify.get('/iocs', async () => {
    const all = await fastify.prisma.iOC.findMany();
    const groups = {
      ipv4: [],
      ipv6: [],
      domain: [],
      url: [],
      cve: [],
      emails: [],
      md5: [],
      sha1: [],
      sha256: []
    };

    for (const ioc of all) {
      if (!groups[ioc.type]) continue;
      groups[ioc.type].push(ioc.value);
    }

    return {
      counts: {
        ipv4: groups.ipv4.length,
        ipv6: groups.ipv6.length,
        domains: groups.domain.length,
        urls: groups.url.length,
        emails: groups.emails.length,
        cves: groups.cve.length,
        md5: groups.md5.length,
        sha1: groups.sha1.length,
        sha256: groups.sha256.length
      },
      hashes: {
        sha256: groups.sha256,
        sha1: groups.sha1,
        md5: groups.md5
      },
      ips: {
        ipv4: groups.ipv4,
        ipv6: groups.ipv6
      },
      iocs: {
        domains: groups.domain,
        urls: groups.url,
        emails: groups.emails,
        cves: groups.cve
      }
    };
  });
}

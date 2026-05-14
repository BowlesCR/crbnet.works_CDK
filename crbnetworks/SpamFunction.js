function handler(event) {
    const request = event.request;
    const uri = request.uri.toLowerCase();

    const prefix_blacklist = ["/.", "/_profiler/", "/phpinfo", "/config/", "/aws.yml", "/wp-", "//", "/admin", "/js/", "/misc/", "/plugins/", "/blog/", "/demo/", "/phpmyadmin/", "/pma/", "/test/", "/wordpress/", "/leaf", '/humans.txt', '/ads.txt', '/sitemap', '/sitemap.txt', '/.env'];
    const suffix_blacklist = [".php", ".env", ".json", ".yml", ".js", ".ini"];

    const blocked = {
        statusCode: 204,
        statusDescription: 'No Content',
        headers: {
            "cache-control": {
                "value": "max-age=31536000"
            }
        }
    };

    if (suffix_blacklist.some(s => uri.endsWith(s))) return blocked;
    if (prefix_blacklist.some(p => uri.startsWith(p))) return blocked;

    return request;
}
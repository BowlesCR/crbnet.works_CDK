function handler(event) {
    var request = event.request;
    var uri = request.uri.toLowerCase();

    var prefix_blacklist = ["/.", "/_profiler/", "/phpinfo", "/config/", "/aws.yml", "/wp-", "//", "/admin", "/js/", "/misc/", "/plugins/", "/blog/", "/demo/", "/phpmyadmin/", "/pma/", "/test/", "/wordpress/", "/leaf", '/humans.txt', '/ads.txt', '/sitemap', '/sitemap.txt', '/.env'];
    var suffix_blacklist = [".php", ".env", ".json", ".yml", ".js", ".ini"];

    var blocked = {
        statusCode: 204,
        statusDescription: 'No Content',
        headers: {
            "cache-control": {
                "value": "max-age=31536000"
            }
        }
    };

    for (var s of suffix_blacklist) {
        if (uri.endsWith(s)) {
            return blocked;
        }
    }
    for (var p of prefix_blacklist) {
        if (uri.startsWith(p)) {
            return blocked;
        }
    }

    return request;
}
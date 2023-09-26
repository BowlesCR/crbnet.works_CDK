function handler(event) {
    var request = event.request;
    var uri = request.uri;

    var prefix_blacklist = ["/.", "/_profiler/", "/phpinfo", "/config/", "/aws.yml", "/wp-", "//", "/admin", "/js/", "/misc/", "/plugins/", "/blog/", "/demo/", "/phpmyadmin/", "/pma/", "/test/", "/wordpress/", "/leaf", '/humans.txt', '/ads.txt', '/sitemap', '/sitemap.txt', '/.env'];
    var suffix_blacklist = [".php", ".env", ".json", ".yml", ".js", ".ini"]

    var p;
    for (p in suffix_blacklist) {
        if (uri.toLowerCase().endsWith(suffix_blacklist[p])) {
            var response = {
                statusCode: 204,
                statusDescription: 'No Content',
                headers: {
                    "cache-control": {
                        "value": "max-age: 31536000"
                    }
                }
            }

            return response;
        }
    }
    for (p in prefix_blacklist) {
        if (uri.toLowerCase().startsWith(prefix_blacklist[p])) {
            var response = {
                statusCode: 204,
                statusDescription: 'No Content',
                headers: {
                    "cache-control": {
                        "value": "max-age: 31536000"
                    }
                }
            }

            return response;
        }
    }

    return request;
}
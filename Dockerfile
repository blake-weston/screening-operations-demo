# SR08: build extensions separately so compilers and development headers do not remain at runtime.
FROM php:8.4-apache AS extension-builder

RUN apt-get update \
    && apt-get install -y --no-install-recommends libfreetype6-dev libjpeg62-turbo-dev libpng-dev \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install pdo_mysql gd

FROM php:8.4-apache

COPY apache/security-hardening.conf /etc/apache2/conf-available/security-hardening.conf

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends libfreetype6 libjpeg62-turbo libpng16-16 \
    && rm -rf /var/lib/apt/lists/* \
    # SR07/SR12: log server-side failures but never render PHP details to clients.
    && printf '%s\n' 'expose_php = Off' 'display_errors = Off' 'log_errors = On' > /usr/local/etc/php/conf.d/security.ini \
    # SR12: these optional modules have no application dependency; retain the remaining standard module set.
    && a2dismod -f autoindex status negotiation \
    && a2enconf security-hardening

COPY --from=extension-builder /usr/local/lib/php/extensions/ /usr/local/lib/php/extensions/
COPY --from=extension-builder /usr/local/etc/php/conf.d/ /usr/local/etc/php/conf.d/

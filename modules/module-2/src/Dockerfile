FROM php:8.0-apache

RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
RUN apt-get update && apt-get upgrade -y
RUN apt-get install mariadb-client-10.5 -y
RUN apt-get install -y net-tools netcat
# Remediation (RT-04): python3/sudo/vim/libcap2-bin/fdisk previously installed
# here had no product purpose and only existed to support a
# "www-data ALL=NOPASSWD:/usr/bin/vim ..." sudoers rule below, a well-known
# root escalation (vim's ex-mode `:!<cmd>` shells out). Both the packages and
# the sudoers rule are removed; there is no legitimate case for this app to
# grant any sudo rule to www-data.

COPY ./src /var/www/html
COPY ./script /usr/local/bin

RUN chmod +x /usr/local/bin/startup.sh

# Remediation (RT-07): payslip/reimbursement documents contain PII (SSN, bank
# account numbers) and were previously served as static files directly under
# the web root with no access control at all - only an unguessable hex
# filename stood between an anonymous visitor and any employee's documents.
# They are moved outside DOCUMENT_ROOT; the only way to fetch one now is
# through download.php, which requires a valid session and verifies the
# requester owns the record (or is admin/superadmin) before streaming it.
RUN mkdir -p /var/www/documents/payslips /var/www/documents/reimbursments \
    && mv /var/www/html/documents/payslips/* /var/www/documents/payslips/ 2>/dev/null || true
RUN mv /var/www/html/documents/reimbursments/* /var/www/documents/reimbursments/ 2>/dev/null || true
RUN rm -rf /var/www/html/documents
RUN chown -R www-data:www-data /var/www/documents && chmod -R 750 /var/www/documents

CMD ["/usr/local/bin/startup.sh"]
EXPOSE 80
#!/bin/bash
# Remediation (RT-01/RT-05): DB_PASSWORD is no longer a hardcoded literal here
# or in config.inc. It is injected by the ECS agent at task-start time from
# Secrets Manager (see the "secrets" block in task_definition.json), using the
# execution role's scoped secretsmanager:GetSecretValue permission - the
# application code never calls Secrets Manager itself.
mysql -h "$RDS_ENDPOINT" -P 3306 -u "$DB_USERNAME" -p"$DB_PASSWORD" -e "source /var/www/html/dump.sql" > /dev/null 2>&1
exec apache2-foreground
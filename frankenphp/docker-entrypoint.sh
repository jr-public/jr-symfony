#!/bin/sh
set -e

if [ "$1" = 'frankenphp' ] || [ "$1" = 'php' ] || [ "$1" = 'bin/console' ]; then

	if [ -z "$(ls -A 'vendor/' 2>/dev/null)" ]; then
		composer install --prefer-dist --no-progress --no-interaction
	fi

	# Display information about the current project
	# Or about an error in project initialization
	printf "[%s] Starting application...\n" "$(date '+%b %d %T')"
	php bin/console -V

	# if grep -q ^DATABASE_URL= .env; then
	if [ -n "$DATABASE_URL" ] || grep -q ^DATABASE_URL= .env 2>/dev/null; then
		echo 'Waiting for database to be ready...'
		ATTEMPTS_LEFT_TO_REACH_DATABASE=60
		until [ $ATTEMPTS_LEFT_TO_REACH_DATABASE -eq 0 ] || DATABASE_ERROR=$(php bin/console dbal:run-sql -q "SELECT 1" 2>&1); do
			if [ $? -eq 255 ]; then
				# If the Doctrine command exits with 255, an unrecoverable error occurred
				ATTEMPTS_LEFT_TO_REACH_DATABASE=0
				break
			fi
			sleep 1
			ATTEMPTS_LEFT_TO_REACH_DATABASE=$((ATTEMPTS_LEFT_TO_REACH_DATABASE - 1))
			echo "Still waiting for database to be ready... Or maybe the database is not reachable. $ATTEMPTS_LEFT_TO_REACH_DATABASE attempts left."
		done

		if [ $ATTEMPTS_LEFT_TO_REACH_DATABASE -eq 0 ]; then
			echo 'The database is not up or not reachable:'
			echo "$DATABASE_ERROR"
			exit 1
		else
			echo 'The database is now ready and reachable'
		fi

		# Check if we need to setup test database (look for _test database usage)
		if php bin/console --env=test dbal:run-sql -q "SELECT 1" 2>/dev/null; then
			echo 'Test database connection available, skipping test setup'
		else
			echo 'Test database not found, setting up...'
			
			# Create test database
			echo 'Creating test database...'
			php bin/console --env=test doctrine:database:create --if-not-exists
			
			# Run test migrations
			echo 'Running test database migrations...'
			php bin/console --env=test doctrine:migrations:migrate --no-interaction --allow-no-migration
			
			echo 'Test database setup complete!'
		fi
		
		if [ "$( find ./migrations -iname '*.php' -print -quit )" ]; then
			php bin/console doctrine:migrations:migrate --no-interaction --all-or-nothing
		fi
	fi

	setfacl -R -m u:www-data:rwX -m u:"$(whoami)":rwX var
	setfacl -dR -m u:www-data:rwX -m u:"$(whoami)":rwX var

	echo 'PHP app ready!'
fi

exec docker-php-entrypoint "$@"

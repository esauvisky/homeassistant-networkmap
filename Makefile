.PHONY: deploy bump-version copy restart

# Default target
all: deploy

# Target to bump version and deploy
deploy: bump-version copy restart

# Bump version in manifest.json
bump-version:
	@echo "Bumping version in manifest.json..."
	@if [ -f networkmap/manifest.json ]; then \
		VERSION=$$(grep -o '"version": "[^"]*"' networkmap/manifest.json | sed 's/"version": "//;s/"//'); \
		MAJOR=$$(echo $$VERSION | cut -d. -f1); \
		MINOR=$$(echo $$VERSION | cut -d. -f2); \
		PATCH=$$(echo $$VERSION | cut -d. -f3); \
		NEW_PATCH=$$((PATCH + 1)); \
		NEW_VERSION="$$MAJOR.$$MINOR.$$NEW_PATCH"; \
		sed -i "s/\"version\": \"$$VERSION\"/\"version\": \"$$NEW_VERSION\"/" networkmap/manifest.json; \
		echo "Version bumped from $$VERSION to $$NEW_VERSION"; \
	else \
		echo "Error: manifest.json not found"; \
		exit 1; \
	fi

# Copy files to Home Assistant custom_components directory
copy:
	@echo "Copying files to Home Assistant custom_components directory..."
	cp ./networkmap /home/emi/Files/HASS/config/custom_components -r
	rm ~/Files/HASS/config/.storage/networkmap_devices_*

# Restart Home Assistant container
restart:
	@echo "Restarting Home Assistant container..."
	ssh emi.casa "docker compose up -d --force-recreate homeassistant"

# Clean target (optional)
clean:
	@echo "Cleaning up..."
	# Add any cleanup commands here if needed

# Clean target (optional)
logs:
	ssh emi.casa docker logs -f homeassistant

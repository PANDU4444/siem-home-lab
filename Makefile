# siem-home-lab
#
# A single entry point, so the repository can be run without reading it first.
#
#   make setup && make up && make deploy && make test
#
# Every target is a thin wrapper around a script in scripts/ or automation/,
# so nothing is hidden here - `make -n <target>` shows exactly what will run.

COMPOSE      := docker compose -f docker/single-node/docker-compose.yml --env-file .env
MANAGER      := single-node-wazuh.manager-1
PYTHON       := python3

.DEFAULT_GOAL := help
.PHONY: help setup up down restart status logs deploy deploy-manager deploy-agent \
        test scan report soc-report timer clean reset

help: ## Show this help
	@echo "siem-home-lab"
	@echo ""
	@echo "Getting started:"
	@echo "  make setup          check prerequisites and generate .env"
	@echo "  make up             start the Wazuh stack"
	@echo "  make deploy         install detection content (needs sudo)"
	@echo "  make test           verify everything works"
	@echo ""
	@echo "All targets:"
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------- setup
setup: ## Check prerequisites and generate .env with random secrets
	@bash scripts/setup.sh

.env:
	@echo "No .env found. Run 'make setup' first." >&2; exit 1

# ---------------------------------------------------------------- stack
up: .env ## Start the Wazuh stack (manager, indexer, dashboard)
	@$(COMPOSE) up -d
	@echo ""
	@echo "Stack starting. The indexer needs about two minutes before the"
	@echo "dashboard will answer at https://localhost"
	@echo "Check progress with: make status"

down: .env ## Stop the stack (data volumes are kept)
	@$(COMPOSE) down

restart: .env ## Restart the stack
	@$(COMPOSE) restart

status: ## Show container status
	@$(COMPOSE) ps 2>/dev/null || docker ps --filter name=wazuh --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'

logs: ## Tail manager logs
	@docker logs -f --tail 50 $(MANAGER)

# ---------------------------------------------------------------- deploy
deploy: deploy-manager deploy-agent ## Deploy detection content to manager and agent

deploy-manager: .env ## Install rules, decoders and integrations into the manager
	@sudo bash scripts/deploy_to_manager.sh

deploy-agent: ## Install YARA, auditd rules and tuned FIM onto the agent
	@sudo bash scripts/deploy_to_agent.sh

timer: ## Install the daily audit systemd timer
	@sudo bash scripts/install_timer.sh

# ---------------------------------------------------------------- verify
test: ## Run the full verification suite
	@bash scripts/run_tests.sh

simulate: ## Run the controlled attack simulation end to end
	@sudo bash scripts/attack-simulation/attack_sim.sh

# ---------------------------------------------------------------- reports
report: ## Generate the daily audit digest (last 24h)
	@mkdir -p .data
	@sudo docker cp $(MANAGER):/var/ossec/logs/alerts/alerts.json .data/alerts.json
	@sudo chown $$(id -u):$$(id -g) .data/alerts.json
	@$(PYTHON) automation/daily_audit.py --hours 24 \
	   --alert-file .data/alerts.json --output-dir analysis/reports

soc-report: ## Generate the full historical SOC report
	@mkdir -p .data
	@sudo docker cp $(MANAGER):/var/ossec/logs/alerts .data/alerts
	@sudo chown -R $$(id -u):$$(id -g) .data/alerts
	@$(PYTHON) analysis/analyze_alerts.py \
	   --archive-dir .data/alerts --alert-file .data/alerts/alerts.json

# ---------------------------------------------------------------- cleanup
clean: ## Remove exported alert data and caches (keeps .env and reports)
	@rm -rf .data .cache .rendered
	@find . -name __pycache__ -type d -prune -exec rm -rf {} + 2>/dev/null || true
	@echo "removed .data, .cache, .rendered and __pycache__"

reset: .env ## Stop the stack and DELETE all Wazuh data volumes
	@echo "This deletes every alert and all Wazuh state. Ctrl-C within 5s to abort."
	@sleep 5
	@$(COMPOSE) down -v
	@echo "stack and volumes removed"

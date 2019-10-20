# Collect Management Group Activity Logs
This PowerShell script is designed to run an an [Azure Automation Runbook](https://docs.microsoft.com/en-us/azure/automation/automation-runbook-types#powershell-runbooks).  The script collects the Activity Logs associated with each [Management Group](https://docs.microsoft.com/en-us/azure/governance/management-groups/overview) within an Azure Active Directory tenant and writes the logs to blob storage in an Azure Storage Account.  It additionally can deliver the logs to an Azure Event Hub and Azure Monitor through the [Azure Monitor HTTP Data Collector API](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/data-collector-api).  

## What problem does this solve?
In Microsoft Azure, write, update, and delete operations on the cloud control plane are logged to the [Azure Activity Log](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-logs-overview).  Each Azure Subscription and Azure Management Group have an Activity Log which are retained on the platform for 90 days.  To retain the logs for more than 90 days the logs need to be retrieved and stored in another medium.  Activity Logs for subscriptions have been integrated with [Azure Storage, Azure Log Analytics, and Azure Event Hubs](https://docs.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-export).  The logs for Management Groups are only accessible through the [Azure Portal and the Azure REST API](https://feedback.azure.com/forums/911473-azure-management-groups/suggestions/34705756-activity-log-for-management-group), and as of October 2019, have not yet been integrated with other storage mediums. 

Management Groups were introduced to Microsoft Azure as a means of applying governance and access controls across multiple Azure Subscriptions.  This is accomplished through the use of [Azure Policy](https://docs.microsoft.com/en-us/azure/governance/policy/overview) and [Azure RBAC](https://docs.microsoft.com/en-us/azure/role-based-access-control/overview).  This means that activites performed on management groups need to be monitored, analyzed, and alerted upon.

This Runbook can be used to collect the Activity Logs from all Management Groups within an Azure AD Tenant in order to retain, analyze, and alert on the logs.  It will write the logs to blob storage in an Azure Storage Account and optionally to a Log Analytics Workspace and Azure Event Hub.  

## Requirements

### Azure Requirements
* 

## Setup

## Example




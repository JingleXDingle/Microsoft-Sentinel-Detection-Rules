param workspaceName string

resource micrunExecutionAlert 'Microsoft.OperationalInsights/workspaces/providers/alertRules@2023-12-01-preview' = {
  name: '${workspaceName}/Microsoft.SecurityInsights/micrun-execution-alert'
  kind: 'Scheduled'
  properties: {
    displayName: 'MicRun Execution Alert – Suspicious Process Activity'
    description: '''
This detection identifies the execution of MicRun.exe or related indicators on endpoints. 
It monitors for processes named MicRun.exe, command lines containing "micrun.exe", or known malicious SHA1 hashes associated with MicRun. 
The presence of these indicators may suggest unauthorized software execution or potential malware activity. 
Security teams should investigate the source and context of the process to determine if it is legitimate or part of a threat.
'''
    severity: 'High'
    enabled: true
    query: '''
DeviceProcessEvents
| where tolower(FileName) == "micrun.exe"
    or tolower(ProcessCommandLine) has "micrun.exe"
    or SHA1 has "e356dbd3bd62c19fa3ff8943fc73a4fab01a6446f989318b7da4abf48d565af2"
| project TimeGenerated, ActionType, DeviceName, AccountName, AccountUpn, InitiatingProcessFileName, ProcessCommandLine, FileName, SHA1, FolderPath
| sort by TimeGenerated desc
'''
    queryFrequency: 'PT5M'
    queryPeriod: 'PT5M'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionDuration: 'PT5H'
    suppressionEnabled: false
    tactics: [
      'Execution'
    ]
    techniques: [
      'T1204'
    ]
    incidentConfiguration: {
      createIncident: true
      groupingConfiguration: {
        enabled: true
        reopenClosedIncident: false
        lookbackDuration: 'PT5H'
        matchingMethod: 'AllEntities'
        groupByEntities: []
        groupByAlertDetails: []
        groupByCustomDetails: []
      }
    }
    eventGroupingSettings: {
      aggregationKind: 'SingleAlert'
    }
    entityMappings: [
      {
        entityType: 'Host'
        fieldMappings: [
          {
            identifier: 'HostName'
            columnName: 'DeviceName'
          }
        ]
      }
      {
        entityType: 'Account'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'AccountName'
          }
        ]
      }
      {
        entityType: 'File'
        fieldMappings: [
          {
            identifier: 'Name'
            columnName: 'FileName'
          }
        ]
      }
    ]
  }
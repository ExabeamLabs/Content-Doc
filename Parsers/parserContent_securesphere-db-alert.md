#### Parser Content
```Java
{
Name = securesphere-db-alert
  Vendor = Imperva
  Product = Imperva SecureSphere
  Lms = Direct
  DataType = "database-alert"
  IsHVF = true
  TimeFormat = "yyyy-MM-dd HH:mm:ss"
  Conditions = [ """IMPERVA-Imperva,""", """,alertSev=""", """,ruleName=""", """,eventType=sql""" ]
  Fields = [
    """exabeam_host=({host}[\w\-.]+)""",
    """\Wevent#?=({alert_id}\d+)""",
    """\W(C|c)reateTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WalertSev=(|({alert_severity}.+?))(,\w+=|\s*$)""",
    """\Wgroup=(|({server_group}.+?))(,\w+=|\s*$)""",
    """\WruleName="({alert_name}[^"]+)"""",
    """\WevntDesc="({additional_info}[^"]+)"""",
    """\Wproto=(|({protocol}.+?))(,\w+=|\s*$)""",
    """\WsrcPort=({src_port}\d+)""",
    """\WsrcIP=(?:0.0.0.0|({src_ip}[a-fA-F:\d\.]+))""",
    """\WdstPort=({dest_port}\d+)""",
    """\WdstIP=({dest_ip}[a-fA-F:\d\.]+)""",
    """\Wusername=(?:hashed user|nt authority\\anonymous logon|(({domain}[^\\,]+)\\)?({user}[^,\\]+?))(,\w+=|\s*$)""",
    """\WdbUsername=(?:nt authority\\anonymous logon|(({domain}[^\\,]+)\\)?({db_user}[^,\\]+?))(,\w+=|\s*$)""",
    """\WdbName=(|({database_name}[^,]+?))(,\w+=|\s*$)""",
    """\Wapplication="({process_name}[^"]+)"""",
    """\WpolicyName="({policy}[^"]+)"""",
    """\Waction="({action}[^"]+)"""",
  ]
  DupFields = [ "alert_name->alert_type" ]
  SOAR {
    IncidentType = "generic"
    DupFields = ["time->startedDate", "vendor->source", "rawLog->sourceInfo", "alert_name->description", "alert_severity->sourceSeverity", "alert_id->sourceId"]
    NameTemplate = """Imperva SecureSphere Alert ${alert_name} found"""
    ProjectName = "SOC"
    EntityFields = [
      {EntityType="device", Name="src_address", Fields=["src_ip->ip_address"]}
```
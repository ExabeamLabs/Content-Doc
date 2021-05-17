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
    """exabeam_host=({host}[\w\-.]{1,2000})""",
    """\Wevent#?=({alert_id}\d{1,100})""",
    """\W(C|c)reateTime=({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d)""",
    """\WalertSev=(|({alert_severity}.+?))(,\w+=|\s{0,100}$)""",
    """\Wgroup=(|({server_group}.+?))(,\w+=|\s{0,100}$)""",
    """\WruleName="({alert_name}[^"]{1,2000})"""",
    """\WevntDesc="({additional_info}[^"]{1,2000})"""",
    """\Wproto=(|({protocol}.+?))(,\w+=|\s{0,100}$)""",
    """\WsrcPort=({src_port}\d{1,100})""",
    """\WsrcIP=(?:0.0.0.0|({src_ip}[a-fA-F:\d\.]{1,2000}))""",
    """\WdstPort=({dest_port}\d{1,100})""",
    """\WdstIP=({dest_ip}[a-fA-F:\d\.]{1,2000})""",
    """\Wusername=(?:hashed user|nt authority\\anonymous logon|(({domain}[^\\,]{1,2000})\\)?({user}[^,\\]{1,2000}?))(,\w+=|\s{0,100}$)""",
    """\WdbUsername=(?:nt authority\\anonymous logon|(({domain}[^\\,]{1,2000})\\)?({db_user}[^,\\]{1,2000}?))(,\w+=|\s{0,100}$)""",
    """\WdbName=(|({database_name}[^,]{1,2000}?))(,\w+=|\s{0,100}$)""",
    """\Wapplication="({process_name}[^"]{1,2000})"""",
    """\WpolicyName="({policy}[^"]{1,2000})"""",
    """\Waction="({action}[^"]{1,2000})"""",
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
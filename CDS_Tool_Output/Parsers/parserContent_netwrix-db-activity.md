#### Parser Content
```Java
{
Name = netwrix-db-activity
   Vendor = NetWrix
  Product = NetWrix Auditor
  Lms = Direct
  DataType = "app-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ssZ"
  Conditions = ["""DataSource : SQL""" , """Where :""" , """Who :"""]
  Fields = [
    """When : ({time}[^\s]+)""",
    """exabeam_host=({host}[\w.\-]+)""",
    """What\s*:\s*(.+?\\+)?({database_name}[^\s]+)""",
    """Who\s*:\s*(({domain}[^\s]+)\\+)?(system|({user}[^\s]+))"""
    """Where\s*:\s*({dest_host}[\w\-.]+)""",
    """Workstation\s*:\s*(|({src_ip}[A-Fa-f:\d.]+))\s*Details\s*:""",
    """ObjectType\s*:\s*({additional_info}.+?)\s*\w+\s*:\s*""",
    """Device name:\s*"*({service_name}[^",\s]+)""",
    """Message\s*:\s*({reason}.+?)\s*\w+\s*:"""
    """DataSource\s*:\s*({app}.+?)\s*\w+\s*:"""
    """Application name:\s*({app}.+?)\s*$"""
  ]
}

{
  Name = cef-aws-guardduty
  Vendor = AWS GuardDuty
  Product = AWS GuardDuty
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """dproc=GuardDuty""", """cat=security-alert""" ]
  Fields = [
    """({host}[\w\-.]+)\s+Skyformation""",
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ).+?CEF""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\ssuser=(|Anonymous|({user}.+?))\s+(\w+=|$)""",
    """\sext_type=({alert_type}.+?)(\s+\w+=|\s*$)""",
    """\sext_id=({alert_id}\w+)(\s+\w+=|\s*$)""",
    """\sext_title=({alert_name}.+?)(\s+\w+=|\s*$)""",
    """\sext_severity=({alert_severity}[\d\.]+)""",
    """\sext_service_action_portProbeAction_portProbeDetails_0__localPortDetails_port=({dest_port}\d+)""",
    """\sext_service_action_networkConnectionAction_localPortDetails_port=({dest_port}\d+)""",
    """\sext_service_action_networkConnectionAction_remotePortDetails_port=({src_port}\d+)""",
    """\sext_service_action_networkConnectionAction_({outcome}blocked=(false|true))""",
    """\smsg=({additional_info}.+?)(\s+\w+=|\s*$)""",
  ]
}
```
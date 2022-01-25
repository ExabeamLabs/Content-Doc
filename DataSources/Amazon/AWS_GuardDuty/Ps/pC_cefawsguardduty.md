#### Parser Content
```Java
{
Name = cef-aws-guardduty
  Vendor = Amazon
  Product = AWS GuardDuty
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """dproc=GuardDuty""", """cat=security-alert""" ]
  Fields = [
    """({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ).+?CEF""",
    """\ssrc=({src_ip}\S+)""",
    """\sdst=({dest_ip}\S+)""",
    """"privateIpAddress":"({dest_ip}[^"]{1,2000})""",
    """\srequestClientApplication=({app}\S+)""",
    """\sdhost=({dest_host}\S+)""",
    """\ssuser=(|Anonymous|({user}.+?))\s{1,100}(\w+=|$)""",
    """\sext_type=({alert_type}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sext_id=({alert_id}\w+)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sext_title=({alert_name}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sext_severity=({alert_severity}[\d\.]{1,2000})""",
    """\sext_service_action_portProbeAction_portProbeDetails_0__localPortDetails_port=({dest_port}\d{1,100})""",
    """\sext_service_action_networkConnectionAction_localPortDetails_port=({dest_port}\d{1,100})""",
    """\sext_service_action_networkConnectionAction_remotePortDetails_port=({src_port}\d{1,100})""",
    """\sext_service_action_networkConnectionAction_({outcome}blocked=(false|true))""",
    """\smsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
  ]


}
```
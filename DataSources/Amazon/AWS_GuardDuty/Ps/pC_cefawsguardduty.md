#### Parser Content
```Java
{
Name = cef-aws-guardduty
  Vendor = Amazon
  Product = AWS GuardDuty
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """dproc=GuardDuty""", """cat=security-alert""", """|security-threat-detected|""" ]
  Fields = [
    """exabeam_host=({host}[\w.\-]{1,2000})""",
    """\s({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)\s""",
    """\ssrc=({src_ip}[A-Fa-f\d:.]{1,2000})""",
    """\sdst=({dest_ip}[A-Fa-f\d:.]{1,2000})""",
    """"privateIpAddress":"({dest_ip}[A-Fa-f\d:.]{1,2000})""",
    """\srequestClientApplication=({app}\S{1,2000})""",
    """\sdhost=({dest_host}\S{1,2000})""",
    """\ssuser=(|Anonymous|({user}[^=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """"type":"({alert_type}[^"]{1,2000}?)"""",
    """"id":"({alert_id}[^"]{1,2000}?)"""",
    """"title":"({alert_name}[^"]{1,2000}?)"""",
    """"severity":"?({alert_severity}[^",]{1,2000})"?,""",
    #"""\sext_service_action_portProbeAction_portProbeDetails_0__localPortDetails_port=({dest_port}\d{1,100})""",
    """"service".*?"action".*?"portProbeAction".*?"portProbeDetails".*?"localPortDetails".*?"port":"({dest_port}\d{1,100})"""",
    #"""\sext_service_action_networkConnectionAction_localPortDetails_port=({dest_port}\d{1,100})""",
    """"service".*?"action".*?"networkConnectionAction".*?"localPortDetails".*?"port":({dest_port}\d+)"""
    #"""\sext_service_action_networkConnectionAction_remotePortDetails_port=({src_port}\d{1,100})""",
    """"service".*?"action".*?"networkConnectionAction".*?"remotePortDetails".*?"port":"({src_port}\d{1,100})"""", 
    #"""\sext_service_action_networkConnectionAction_({outcome}blocked=(false|true))""",
    """"service".*?"action".*?"networkConnectionAction.*?"({outcome}blocked":"(false|true))""",
    """\smsg=({additional_info}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """"tags":[^\]]{1,2000}?\{"key":"Username","value":"({user_email}[^@"]{1,2000}@[^\."]{1,2000}\.[^"]{1,2000})""""
  ]


}
```
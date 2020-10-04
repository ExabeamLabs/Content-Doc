#### Parser Content
```Java
{
Name = s-sep-mobile-alert-1
  Conditions = [ """"type": "Malware"""" , """current_risk_warnings""", """package_name""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"email":\s*"({user_email}[^"]+)",\s*"name":\s*"({user_fullname}[^"]+)"""",
    """"severity":\s*"({alert_severity}[^"]+)",\s*"id":\s*({alert_id}\d+)""",
    """"package_name":\s*"({alert_type}[^"]+)""",
    """"apk_hash":\s*"({md5}[^"]+)""",
  ]
}

${SymantecParserTemplates.s-sep-mobile-alert}{
  Name = s-sep-mobile-alert-2
  Conditions = [ """"type":"DeviceCompromised"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """kill_chain_incident_ids""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
  ]
}

${SymantecParserTemplates.s-sep-mobile-alert}{
  Name = s-sep-mobile-alert-3
  Conditions = [ """"type":"Network"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """"current_health_warnings""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
  ]
}

${SymantecParserTemplates.s-sep-mobile-alert}{
  Name = s-sep-mobile-alert-4
  Conditions = [ """"type":"VulnerableOs"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """current_health_warnings""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
  ]
}

${SymantecParserTemplates.s-sep-mobile-alert}{
  Name = s-sep-mobile-alert-5
  Conditions = [ """"type":"UnwantedApp"""" , """current_risk_warnings""", """health_status""", """mdm_status""", """current_health_warnings""" ]
  Fields = ${SymantecParserTemplates.s-sep-mobile-alert.Fields}[
    """"severity":\s*"({alert_severity}[^"]+)".+?"id":\s*({alert_id}\d+)""",
    """"type":\s*"({alert_type}[^"]+)""",
  ]
}
 
{
  Name = symantec-atp-alert
  Vendor = Symantec
  Product = Symantec Advanced Threat Protection
  Lms = Direct
  DataType = "alert"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """|Symantec|ATPU|""", """|atp_incident|""", """"events":""" ]
  Fields = [
    """\Wdevice_time=({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)""",
    """"device_name":"({host}[^"]+)"""",
    """"events":\[.+?"signature_name":"({alert_name}[^"]+)".+?\]""",
    """"events":\[.+?"threat":\{.*?"name":"({alert_name}[^"]+)".*?\}.+?\]""",
    """"rule_name":"({alert_type}[^"]+)"""",
    """"events":\[.+?"alert":"({alert_type}[^"]+)".+?\]""",
    """"events":\[.+?"file":\{.*?"md5":"?(?:null|({md5}[^"]+))"?.*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"folder":"({file_parent}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"file":\{.*?"name":"({file_name}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"email_subject":"({additional_info}[^"]+)".+?\]""",
    """"events":\[.+?"incident_priority_level":"({alert_severity}[^"]+)".+?\]""",
    """"events":\[.+?"user_name":"(?:SYSTEM|(A|a)dministrator|({user_fullname}[^\s"]+\s+[^\s"]+)|({user}[^"]+))".+?\]""",
    """"events":\[.+?"sender":\{.*?"email_address":"({user_email}[^"]+)".*?\}.+?\]""",
    """"events":\[.+?"device_name":"({src_host}[^"]+)".+?\]""",
    """"events":\[.+?"device_ip":"({src_ip}[^"]+)".+?\]""",
    """"events":\[.+?"email_action":"({outcome}[^"]+)".+?\]""",
    """"events":\[.+?"actual_action":"({outcome}[^"]+)".+?\]""",
    """"events":\[.+?"time":"({time}\d+\-\d+\-\d+T\d+:\d+:\d+\.\d+Z)".+?\]""",
    """"atp_incident_id":({alert_id}\d+)"""
  ]
  DupFields = ["host->dest_host", "file_name->process_name"]
}
```
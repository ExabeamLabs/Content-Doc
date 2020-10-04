#### Parser Content
```Java
{
Name = chcom-web-activity
  Vendor = Apache
  Product = Apache
  Lms = Direct
  DataType = "web-activity"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ"
  Conditions = [ """chcom_access_log""", """apache_access_log""", """"request":"""", """"response":"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """@timestamp":"({time}\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\d\.\d\d\dZ)""",
    """host"*:"*\{"*name"*:"*({host}[^"]+)"""",
    """remote_addr":"(?:-|({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})|({src_host}\S+))"*""",
    """verb":"({method}[^"]+)"""",
    """request":"({uri_path}[^"\?\s]+)(?:\?({uri_query}[^?\s"]+))?"""",
    """response":"({result_code}\d+)""",
    """bytes":"(-|({bytes_out}\d+))""",
    """referrer":"(-|({referrer}[^"]+))"""",
    """user_agent":"(-|({user_agent}[^"]+))"""",
    """Mozilla\/[^"]+\(({os}iOS|Android|BlackBerry|Windows Phone|BeOS|(?:X|x)11|(?:W|w)indows|(?:L|l)inux|(?:M|m)acintosh|(?:D|d)arwin)""",
    """Mozilla\/[^"]+?({browser}Chrome|Safari|Opera|(?:F|f)irefox|MSIE|Trident)""",
    """location":"(-|({full_url}[^"]))""""
  ]
}

${ArubaClearParserTemplates.cef-aruba-nac-logon-1}{
  Name = cef-radius-authentication-failed
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Failed Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
    """Reason\\=\[({failure_reason}.+?)\]""",
    
  ]
}
${ArubaClearParserTemplates.cef-aruba-nac-logon-1}{
  Name = cef-radius-authentication
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|RADIUS Authentications|""" ]
  Fields=${ArubaClearParserTemplates.cef-aruba-nac-logon-1.Fields}[
   ]
  DupFields = [ "src_ip->dest_ip" ]
}
${ArubaClearParserTemplates.cef-aruba-nac-logon-1}{
  Name = cef-tacacs-authentication-failed
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|TACACS Failed Authentication|""" ]
}
${ArubaClearParserTemplates.cef-aruba-nac-logon-1}{
  Name = cef-tacacs-authentication
  Product = Aruba Wireless controller
  Conditions = [ """CEF:""", """|Aruba Networks|ClearPass|""", """|TACACS Authentication|""" ]
}

${LastlineParserTemplates.lastline-security-alert}{
  Name = lastline-security-alert-1
  Conditions = [ """CEF:""", """|Lastline|""", """|dns-resolution|""", """|Suspicious DNS Resolution|""" ]
}
${LastlineParserTemplates.lastline-security-alert}{
  Name = lastline-security-alert-2
  Conditions = [ """CEF:""", """|Lastline|""", """|email-attachment|""", """|Suspicious Email Attachment|""" ]
}
${LastlineParserTemplates.lastline-security-alert}{
  Name = lastline-security-alert-3
  Conditions = [ """CEF:""", """|Lastline|""", """|signature-match|""", """|IDS Signature Match|""" ]
}

${Auth0AAParserTemplates.auth0-authentication-template}{
  Name = auth0-password-change-failed
  DataType = "password-change"  
  Conditions = [ """"type":"fcp"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}fcp)"""",
  ]
  DupFields = [ "user->target_user" ]
}
${Auth0AAParserTemplates.auth0-authentication-template}{
  Name = auth0-login-success
  DataType = "app-login"
  Conditions = [ """"type":"s"""", """"user_id"""", """"client_name"""", """"client_id""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}s)"""",
  ]
}
${Auth0AAParserTemplates.auth0-authentication-template}{
  Name = auth0-login-failed
  DataType = "failed-logon"
  Conditions = [ """"type":"fp"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}fp)"""",
    """consoleOut"+:"+({failure_reason}[^"]+)"+""",
  ]
}
${Auth0AAParserTemplates.auth0-authentication-template}{
  Name = auth0-login-failed-1
  DataType = "failed-logon"
  Conditions = [ """"type":"f"""", """"user_id"""", """"client_name"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({activity_type}f)"""",
    """message"+:"+({failure_reason}[^"]+)"+,""",
  ]
}
${Auth0AAParserTemplates.auth0-authentication-template}{
  Name = auth0-password-breached
  DataType = "security-alert"
  Conditions = [ """"type":"pwd_leak"""", """"user_id"""", """"client_id"""" ]
  Fields=${Auth0AAParserTemplates.auth0-authentication-template.Fields}[
    """"({alert_name}pwd_leak)"""",
  ]
}

{
  Name = p2000-physical-badge-access
  Vendor = Johnson Controls
  Product = Johnson Controls P2000
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "yyyy-MM-dd'T'HH:mm:ss.SSS"
  Conditions = [ """"x_badge_number"""", """"x_fac_code"""", """"x_timed_overrd"""", """"x_cardholder_guid"""", """"x_cardholder_nick_name"""" ]
  Fields = [
    """exabeam_host=([^=]+@\s*)?({host}\S+)""",
    """"x_timestamp":"({time}[^"]+?)Z?"""",
    """"x_badge_number":"({badge_id}[^"]+?)\s*"""",
    """"x_fname":"({first_name}[^"]+?)\s*"""",
    """"x_lname":"({last_name}[^"]+?)\s*"""",
    """"x_event_name":"({event_name}[^"]+?)\s*"""",
    """"x_panel_name":"({location_building}[^"]+?)\s*"""",
    """"x_term_name":"({location_door}[^"]+?)\s*"""",
    """"x_item_name":"({additional_info}[^"]+?)\s*"""",
    """"site":"({location_city}[^"]+?)\s*"""",
  ]
}
```
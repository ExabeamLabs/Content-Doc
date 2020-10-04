#### Parser Content
```Java
{
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
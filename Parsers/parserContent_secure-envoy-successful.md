#### Parser Content
```Java
{
Name = secure-envoy-successful
  Vendor = Secure Envoy
  Product = Secure Envoy
  Lms = Direct
  DataType = ""authentication-successful""
  TimeFormat = "dd MM yyyy HH:mm:ss"
  Conditions = ["""TORVMVERIFY""","""Passcode OK"""]
  Fields = [
    """({time}\d+\s\w+\s\d+\s\d+:\d+:\d+)\s*""",
    """TORVMVERIFY01\s({server_name}[^\s]+)\sUserID=(({user}[^\s@]+?)@({domain}[^\s]+)|({=user}[^\s]+))\s({auth_method}Passcode OK)""",
    """ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
    """RemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
	
  ]
}

{
  Name = secure-envoy-failed
  Vendor = Secure Envoy
  Product = Secure Envoy
  Lms = Direct
  DataType = ""authentication-failed""
  TimeFormat = "dd MM yyyy HH:mm:ss"
  Conditions = [ """TORVMVERIFY""","""Access Denied""" ]
  Fields = [
    """({time}\d+\s\w+\s\d+\s\d+:\d+:\d+)\s*""",
    """TORVMVERIFY01\s({server_name}[^\s]+)\sUserID=(({user}[^\s@]+?)@({domain}[^\s]+)|({=user}[^\s]+))\sAccess\s({auth_method}Denied)\s({failure_reason}.+)ClientIP=({src_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})\sRemoteID=({dest_ip}\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3})""",
  ]
}

{
  Name = gallagher-badge-access-denied
  Vendor = Gallagher
  Product = Gallagher Badge Access
  Lms = Direct
  DataType = "physical-access"
  TimeFormat = "dd/MM/yyyy HH:mm:ss a"
  Conditions = ["""Card number (""", """denied""", """<custom_condition_cont7802>"""]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """({time}\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)","({description}[^"]+)"""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)","[^"]+","({location_full}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){2}"({badge_id}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){3}"({event_type}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){4}"({source}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){5}"({first_name}[^"]+)",""",
    """(?:\d\d\/\d\d\/\d{4}\s\d\d:\d\d:\d\d\s\S\S)",("[^"]+",){6}"({last_name}[^"]+)""",
  ]
}
```
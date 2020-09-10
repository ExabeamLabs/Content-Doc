#### Parser Content
```Java
{
Name = q-cisco-acs-nac-logon
  Vendor = Cisco
  Product = Cisco ISE
  Lms = QRadar
  DataType = "nac-logon"
  TimeFormat = "yyyy-MM-dd HH:mm:ss.SSS Z"
  Conditions = [ """Passed-Authentication: Authentication succeeded""", """CSCOacs_Passed_Authentications""", """ACSVersion=""", ]
  Fields = [
    """exabeam_host=({host}[^\s]+)""",
    """\s({host}[\w\-.]+)\s+CSCOacs_Passed_Authentications""",
    """\s+\d+\s+({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d\s(\+|-)\d\d:\d\d)""",
    """,\s*User-?Name=(({user_type}host)\/)?(({domain}[^\s\\]+)\\+)?({user}[^,@]+)""",
    """,\s*User-?Name=(?=[^\s]+@[^\s]+)({user_email}[^\s,]+)""",
    """,\s*Calling-Station-ID=({dest_host}[^,]+)""",
    """,\s*NAS-Identifier=({dest_host}[^@,]+)""",
    """,\s*NAS-Identifier=({computer_name}[^@,]+)""",
    """,\s*Device IP Address=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s*Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s*Framed-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s*SelectedAuthorizationProfiles=({access_type}[^,]+)""",
    """,\s*AuthenticationMethod=({auth_type}[^,]+)""",
  ]
}
```
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
    """\s({host}[\w\-.]+)\s{1,100}CSCOacs_Passed_Authentications""",
    """\s{1,100}\d{1,100}\s{1,100}({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d\.\d\d\d\s(\+|-)\d\d:\d\d)""",
    """,\s{0,100}User-?Name=(({user_type}host)\/)?(({domain}[^\s\\]+)\\+)?({user}[^,@]+)""",
    """,\s{0,100}User-?Name=(?=[^\s]+@[^\s]+)({user_email}[^\s,]+)""",
    """,\s{0,100}Calling-Station-ID=({dest_host}[^,]+)""",
    """,\s{0,100}NAS-Identifier=({dest_host}[^@,]+)""",
    """,\s{0,100}NAS-Identifier=({computer_name}[^@,]+)""",
    """,\s{0,100}Device IP Address=({auth_server}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s{0,100}Device IP Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s{0,100}Framed-IP-Address=({dest_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
    """,\s{0,100}SelectedAuthorizationProfiles=({access_type}[^,]+)""",
    """,\s{0,100}AuthenticationMethod=({auth_type}[^,]+)""",
  ]
}
```
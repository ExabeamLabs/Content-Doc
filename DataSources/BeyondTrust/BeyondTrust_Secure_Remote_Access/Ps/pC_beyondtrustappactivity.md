#### Parser Content
```Java
{
Name = beyondtrust-app-activity
  Product = BeyondTrust Secure Remote Access
  DataType = "app-activity"
  Conditions = [ """site=""", """event=""", """;who=""", """;who_ip=""" ]

beyondtrust-events = {
  Vendor = BeyondTrust
  Product = BeyondTrust
  Lms = Direct
  TimeFormat = "epoch_sec"
  Fields = [
    """exabeam_host=([^=]{1,2000}@\s{0,100})?({host}\S+)""",
    """\s({time}\d{1,100}-\d{1,100}-\d{1,100}T\d{1,100}:\d{1,100}:\d{1,100}[\+\-]\d{1,100}:\d{1,100})\s{1,100}({host}[\w\-.]{1,2000})\s""",
    """\Wwhen=({time}\d{1,100})""",
    """\Wevent=({activity}[^;]{1,2000}?)\s{0,100};""",
    """\Wsite=({app}[^;]{1,2000})""",
    """\Wstatus=({outcome}[^;"]{1,2000}?)\s{0,100}(;|"|$)""",
    """\Wtarget=({object}[^;]{1,2000}?)\s{0,100};""",
    """\Wwho_ip=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wwho=[^;\(]{0,2000}?\((({domain}[^;\s\)@\\\/]{1,2000})\\+)?({user}[^;\s\)@\\\/]{1,2000})(\s|;|\))""",
    """\Wwho=[^;\(]{0,2000}?\(({user_email}[^;\s\)@\\\/]{1,2000}@[^;\s\)@\\\/]{1,2000})(\s|;|\))""",
    """\Wusername=(({domain}[^;\s\)@\\\/]{1,2000})\\+)?({user}[^;\s\)@\\\/]{1,2000})(\s|;|\))""",
    """\Wusername=({user_email}[^;\s\)@\\\/]{1,2000}@[^;\s\)@\\\/]{1,2000})(\s|;|\))""",
  
}
```
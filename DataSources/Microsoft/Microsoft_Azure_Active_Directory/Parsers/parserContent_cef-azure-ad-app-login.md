#### Parser Content
```Java
{
Name = cef-azure-ad-app-login
  Vendor = Microsoft
  Product = Microsoft Azure Active Directory
  Lms = ArcSight
  DataType = "app-activity"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|Azure|""", """|Sign-in activity|""", """ad.azureconditionalAccessStatus=""" ]
  Fields = [
    """\Wrt=({time}\d{1,100})""",
    """\Wdvc=({host}[\w\-.]+)""",
    """\Wapp=({app}[^"\=]+?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Woutcome=({result_code}[^"\=]+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}[^"\=\s]+?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_fullname}[^"\=\s]+?\s{1,100}[^"\=\s]+?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({user_email}[^"\=\s@]+@({email_domain}[^"\=\s@]+?))\s{1,100}(\w+=|$)""",
    """\Wcs1=({os}[^"\=]+?)\s{1,100}(\w+=|$)""",
    """\Wreason=(Other|({failure_reason}[^"\=]+?))\s{1,100}(\w+=|$)""",
    """\Wcs4=({location_country}[^"\=]+?)\s{1,100}(\w+=|$)""",
    """\Wcs3=.*?"city":"({location_city}[^"]+)""",
    """\Wcs3=.*?"state":"({location_state}[^"]+)""",
    """\Wcs3=.*?"geocoordinates":\{({additional_info}[^\}]+)""",
    """\Wad\.azureconditionalAccessStatus=({outcome}[^"\=\.]+?)\s{1,100}([\w\.]+=|$)""",
    """CEF:([^\|]*\|){4}({activity}[^\|]+)""",
  ]
}
```
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
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[\w\-.]+)""",
    """\Wapp=({app}[^"\=]+?)\s+(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
    """\Wshost=({src_host}[\w\-.]+)""",
    """\Woutcome=({result_code}[^"\=]+?)\s+(\w+=|$)""",
    """\Wduser=({user}[^"\=\s]+?)\s+(\w+=|$)""",
    """\Wduser=({user_fullname}[^"\=\s]+?\s+[^"\=\s]+?)\s+(\w+=|$)""",
    """\Wcs6=({user_email}[^"\=\s@]+@({email_domain}[^"\=\s@]+?))\s+(\w+=|$)""",
    """\Wcs1=({os}[^"\=]+?)\s+(\w+=|$)""",
    """\Wreason=(Other|({failure_reason}[^"\=]+?))\s+(\w+=|$)""",
    """\Wcs4=({location_country}[^"\=]+?)\s+(\w+=|$)""",
    """\Wcs3=.*?"city":"({location_city}[^"]+)""",
    """\Wcs3=.*?"state":"({location_state}[^"]+)""",
    """\Wcs3=.*?"geocoordinates":\{({additional_info}[^\}]+)""",
    """\Wad\.azureconditionalAccessStatus=({outcome}[^"\=\.]+?)\s+([\w\.]+=|$)""",
    """CEF:([^\|]*\|){4}({activity}[^\|]+)""",
  ]
}
```
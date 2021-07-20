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
    """\Wdvc=({host}[\w\-.]{1,2000})""",
    """\Wapp=({app}[^"\=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wsrc=({src_ip}[A-Fa-f:\d.]{1,2000})""",
    """\Wshost=({src_host}[\w\-.]{1,2000})""",
    """\Woutcome=({result_code}[^"\=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user}[^"\=\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wduser=({user_fullname}[^"\=\s]{1,2000}?\s{1,100}[^"\=\s]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wcs6=({user_email}[^"\=\s@]{1,2000}@({email_domain}[^"\=\s@]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wcs1=({os}[^"\=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wreason=(Other|({failure_reason}[^"\=]{1,2000}?))\s{1,100}(\w+=|$)""",
    """\Wcs4=({location_country}[^"\=]{1,2000}?)\s{1,100}(\w+=|$)""",
    """\Wcs3=.*?"city":"({location_city}[^"]{1,2000})""",
    """\Wcs3=.*?"state":"({location_state}[^"]{1,2000})""",
    """\Wcs3=.*?"geocoordinates":\{({additional_info}[^\}]{1,2000})""",
    """\Wad\.azureconditionalAccessStatus=({outcome}[^"\=\.]{1,2000}?)\s{1,100}([\w\.]{1,2000}=|$)""",
    """CEF:([^\|]{0,2000}\|){4}({activity}[^\|]{1,2000})""",
  ]
}
```
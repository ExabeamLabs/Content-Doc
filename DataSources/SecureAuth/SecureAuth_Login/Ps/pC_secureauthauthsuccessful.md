#### Parser Content
```Java
{
Name = secureauth-auth-successful
    Vendor = SecureAuth
  Product = SecureAuth Login
    Lms = ArcSight
    DataType = "authentication-successful"
    TimeFormat = "epoch"
    Conditions = [ """|SecureAuth|""","""|ID20990|Success|"""]
    Fields = [
        """\srt=({time}\d{1,100})""",
        """\sdvc=({host}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\sflexString1=({host}[^\s]{1,2000})""",
        """\ssrc=({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})""",
        """\ssuser=({user}.+?)\s{1,100}\w+=""",
        """requestClientApplication=(?:-|({user_agent}[\s]{1,2000}))""",
    ]
  

}
```
#### Parser Content
```Java
{
Name = cef-msn-nac-logon
  Vendor = Microsoft
  Product = Microsoft NPS
  Lms = ArcSight
  DataType = "nac-logon"
  TimeFormat = "epoch"
  Conditions = [ """CEF:""", """|Microsoft|Microsoft NPS""", """ act=Access-Request""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\sdvc=({host}[a-fA-F\d.:]{1,2000})""",
    """\ssrc=({src_ip}[a-fA-F\d.:]{1,2000})""",
    """\sdst=({auth_server}[a-fA-F\d.:]{1,2000})""",
    """\sdvchost=({host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sshost=({src_host}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdhost=({auth_server}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssourceTranslatedAddress=({dest_ip}[a-fA-F\d.:]{1,2000})""",
    """\ssuser=({user}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sdntdom=({domain}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\sapp=({protocol}.+?)(\s{1,100}\w+=|\s{0,100}$)""",
    """\ssourceGeoCountryCode=({src_country_code}\w+)"""
  ]


}
```
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
    """\srt=({time}\d+)""",
    """\sdvc=({host}[a-fA-F\d.:]+)""",
    """\ssrc=({src_ip}[a-fA-F\d.:]+)""",
    """\sdst=({auth_server}[a-fA-F\d.:]+)""",
    """\sdvchost=({host}.+?)(\s+\w+=|\s*$)""",
    """\sshost=({src_host}.+?)(\s+\w+=|\s*$)""",
    """\sdhost=({auth_server}.+?)(\s+\w+=|\s*$)""",
    """\ssourceTranslatedAddress=({dest_ip}[a-fA-F\d.:]+)""",
    """\ssuser=({user}.+?)(\s+\w+=|\s*$)""",
    """\sdntdom=({domain}.+?)(\s+\w+=|\s*$)""",
    """\sapp=({protocol}.+?)(\s+\w+=|\s*$)""",
    """\ssourceGeoCountryCode=({src_country_code}\w+)"""
  ]
}
```
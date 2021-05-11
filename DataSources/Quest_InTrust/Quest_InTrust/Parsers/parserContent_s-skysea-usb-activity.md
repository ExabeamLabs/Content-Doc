#### Parser Content
```Java
{
Name = s-skysea-usb-activity
    DataType = "usb-activity"
    Conditions = [ """,ドライブ,""", """,ドライブの追加,""" ]
    Fields = ${SKySeaParserTemplates.s-skysea-dlp.Fields} [
    """({host}[^,]+),([^,]*,){7}ドライブ,""",
    """({src_ip}[a-fA-F\d.:]+),([^,]*,){6}ドライブ,""",
    """({user}[^,]+),([^,]*,){4}ドライブ,""",
    """({time}\d{4}\/\d\d\/\d\d \d\d:\d\d:\d\d),ドライブ,""",
    """,ドライブ,([^,]*,){2}({target}[^,]+),""",
    """,ドライブ,([^,]*,){15}(-|({device_id}[^,]+)),""",
    """,ドライブ,([^,]*,){12}({device_name}[^,]+),""",
    """,({activity}ドライブの追加),""",
    """,ドライブ,([^,]*,){29}({device_type}[^,]+),""",

    ]
  }
s-skysea-dlp = {
    Vendor = SkySea
    Product = ClientView
    Lms = Splunk
    TimeFormat = "yyyy/MM/dd HH:mm:ss"
    Fields = [
      """({host}[\w\-.]+),\d{1,100},""",
      """^([^\,]*\,){3}({src_ip}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\,""",
      """^([^\,]*\,){5}({user}[^\,]+)\,""",
      """^([^\,]*\,){7}({time}\d{1,100}\/\d{1,100}\/\d{1,100} \d{1,100}:\d{1,100}:\d{1,100})""",
    ]

```
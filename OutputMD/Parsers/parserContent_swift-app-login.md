#### Parser Content
```Java
{
Name = swift-app-login
    Vendor = Swift
    Product = Swift
    Lms = Splunk
    DataType = "app-login"
    TimeFormat = "epoch"
    Conditions = [ """|SWIFT|""", """|Successful signon|"""]
    Fields = [
      """rt=({time}\d+)""",
      """\Wdvc=({host}[A-Fa-f:\d.]+)""",
      """\Wdvchost=({host}[\w\-.]+)""",
      """suid=({user}[^\s]+)""",
      """({app}SWIFT)""",
      """\Wsrc=({src_ip}[A-Fa-f:\d.]+)""",
      """msg=([^:]+):\s*({user_fullname}[^,]+)""",
      """({activity}(({outcome}Successful)) signon)""",
      """msg=({additional_info}.+?)Operator Profiles:\s*({profiles}.+?)(\s*\w+=|\s*$)"""
      """msg=.+?using\s*\'({platform}[^\']+)"""
    ]
  }
```
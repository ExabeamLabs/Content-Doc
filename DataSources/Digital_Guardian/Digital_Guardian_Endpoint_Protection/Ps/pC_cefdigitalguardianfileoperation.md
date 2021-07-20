#### Parser Content
```Java
{
Name = cef-digitalguardian-file-operation
  Vendor = Digital Guardian
  Product = Digital Guardian Endpoint Protection
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|Digital Guardian|Digital Guardian|""" ]
  Fields = [
    """\srt=({time}\d{1,100})""",
    """\ssrc=({host}\S+)""",
    """\ssrc=({dest_host}\S+)""",
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}\S+)""",
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({dest_host}\S+)""",
    """\sdst=({host}\S+)""",
    """\sdhost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}\S+)""",
    """\sdvc=({host}\S+)""",
    """\sdvc=({dest_host}\S+)""",
    """\sdvchost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({host}\S+)""",
    """\sdvchost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({dest_host}\S+)""",
    """\ssrc=({src_ip}\S+)""",
    """\sshost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({src_host}\S+)""",
    """\sdst=({dest_host}\S+)""",
    """\sdhost=(([^\/\\=]{1,2000})[\/\\]{1,2000})?({dest_host}\S+)""",
    """\ssuser=(({domain}[^\/\\=]{1,2000})[\/\\]{1,2000})?({user}[^=]{1,2000}?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\ssproc=({process_name}.+?)\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\|Digital Guardian\|(.*?\|){2}({event_code}.+?)\|""",
    """\soldFilePath=(|\?:\\+|({src_file_dir}.+?))\\*\s{1,100}(ad\.\S+=|\w+=|$)""",   
    """\sfilePath=(|\?:\\+|({file_parent}.+?))\\*\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\soldFileName=(|({src_file_name}.+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfname=(|({file_name}.+?(\.({file_ext}[^\.]{1,2000}?))?))\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sfileType=(|({file_ext}.+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\|(File Recycle|File Delete)\|.*\soldFilePath=(|({file_parent}.+?))\\*\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\|(File Recycle|File Delete)\|.*\soldFileName=(|({file_name}.+?(\.({file_ext}[^\.]{1,2000}?))?))\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__ProductName=(|({app}.+?))\s{1,100}(ad\.\S+=|\w+=|$)""",
    """\sad\.DG__BytesWritten=(0|({bytes}\d{1,100}))\s{1,100}(ad\.\S+=|\w+=|$)""",
  ]
}
```
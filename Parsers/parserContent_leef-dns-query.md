#### Parser Content
```Java
{
Name = leef-dns-query
    Vendor = BlueCat Networks Adonis
  Product = BlueCat Networks Adonis
    Lms = QRadar
    DataType = "dns-query"
    IsHVF = true
    TimeFormat = "epoch"
    Conditions = [ "LEEF", "|DNS_Query|", "|BCN|" ]
    Fields = [
      """exabeam_host=(.+?@\s*)?({host}[^\s]+)""",
      """exabeam_endTime=({time}\d+)""",
      """exabeam_payload=({dest_host}[^\s]+) LEEF:""",
      """\|cat=({query_type}[^\s_]+)""",
      """src=({src_ip}[\da-fA-F\.:]+)""",
      """url=\s*({query}[^\s]+)""",
      """url=\s*([^.\s]+\.)*({top_query}[^.\s]+\.(?i)(com|net|info|edu|org|gov|co|jp|ru|de|ir|it|in|fr|info|pl|nl|es|gr|cz|eu|tv|me|jp|ca|cn|uk|my|cc|id|us|nz|biz|club|io|gg|fi|au|st|tw|asia|sg|ie|li|za)+)"""
    ]
  }

{
  Name = cef-netapp-file-read
  Vendor = NetApp
  Product = NetApp
  Lms = ArcSight
  DataType = "file-operations"
  IsHVF = true
  TimeFormat = "epoch"
  Conditions = [ """|NetApp|Filer|""", """|Object Open|""" ]
  Fields = [
    """\Wrt=({time}\d+)""",
    """\Wdvc=({host}[A-Fa-f:\d.]+)""",
    """\Wdvchost=({host}[\w\-.]+)""",
    """\Wdhost=({dest_host}[\w\-.]+)""",
    """\Wdst=({dest_ip}[A-Fa-f:\d.]+)""",
    """\Wdntdom=({user}[^\s]+)\s*(\w+=|$)""",
    """\Wduser=(NetApp Data ONTAP|({user}[^\s]+))\s*(\w+=|$)""",
    """\Wfname=({file_path}.+?)\s*(\w+=|$)""",
    """\Wfname=({file_parent}.+?)[^\\]+\s*(\w+=|$)""",
    """\Wfname=.*?({file_name}[^\\]+?)\s*(\w+=|$)""",
    """\Wfname=.*?(\.({file_ext}[^\\\.]+?))?\s*(\w+=|$)""",
    """\WfileId=(-|({file_id}\d+))""",
    """\WfileType=({file_type}.+?)\s*(\w+=|$)""",
    """CEF:([^\|]*\|){5}({accesses}[^\|]+)""",
    """\Wcs1=(-|({accesses}.+?))\s*(\w+=|$)"""
  ]
}
```
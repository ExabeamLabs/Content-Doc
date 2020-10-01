#### Parser Content
```Java
{
Name = s-560-jp
    Vendor = Microsoft
    Product = Microsoft Windows
    Lms = Splunk
    DataType = "file-operations"
    IsHVF = true
    TimeFormat = "yyyy-MM-dd HH:mm:ss"
    Conditions = [ ",560,", """|NetApp Data ONTAP|""", "オブジェクト アクセス" ]
    Fields = [ 
      """exabeam_host=({host}[\w.\-]+)""",
      """({time}\d\d\d\d-\d\d-\d\d \d\d:\d\d:\d\d),560,""",
      """({event_code}560)""",
      """オブジェクトの種類:\s+({file_type}[^\s]+)\s+""",
      """オブジェクト名:\s+({file_path}.+?)\s+ハンドル ID:""",
      """オブジェクト名:\s+.*\\({file_name}(?:[^\\:]+(?=\.))({file_ext}\.[^\\:\s]+)?|[^\\:\s]+)\s*ハンドル ID:""",
      """オブジェクト名:\s+({file_parent}.+?)\\(?:[^\\]+?)\s*ハンドル ID:""",
      """プライマリ ユーザー名:\s+({user}[^\s]+)\s+""",
      """プライマリ ドメイン:\s+({domain}[^\s]+)\s+""",
      """プライマリ ログオン ID:\s+\([^,]+,\s*({logon_id}[^)]+)""",
      """イメージ ファイル名:\s+({process_name}.+?)\s+プライマリ ユーザー名:""",
      """クライアント ユーザー名:\s+({src_ip}[A-Fa-f:\d.]+)""",
      """アクセス数:\s+({accesses}.+?)\s+特権:"""
    ]
  }
```
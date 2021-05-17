#### Parser Content
```Java
{
Name = bro-files
  Vendor = Zeek
  Product = Zeek Network Security Monitor
  Lms = Direct
  DataType = "file-read"
  TimeFormat = "epoch_sec"
  Conditions = [ "/files.log" ]
  Fields = [
      """exabeam_host=([^@=]{1,2000}@\s{0,100})?({host}\S+)""",
      """({time}\d{10})\.\d{6}\t({file_id}[^\t]{1,2000})\t(?:-|(({src_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|(({dest_ip}(\d{1,3}\.){3}\d{1,3}|([A-Fa-f0-9%.]{0,2000}:[A-Fa-f0-9%.:]{1,2000}(th0)?))|[^\t]{1,2000}))\t(?:-|({conn_uids}[^\t]{1,2000}))\t(?:-|({protocol}[^\t]{1,2000}))\t(?:-|({depth}[^\t]{1,2000}))\t(?:-|({analyzers}[^\t]{1,2000}))\t(?:-|({mime}[^\t]{1,2000}))\t(?:-|([^\t]{1,2000}))\t(?:-|({duration}[^\t]{1,2000}))\t(?:-|({local_orig}[^\t]{1,2000}))\t(?:-|({is_orig}[^\t]{1,2000}))\t(?:-|({bytes}[^\t]{1,2000}))\t(?:-|({total_bytes}[^\t]{1,2000}))\t(?:-|({missing_bytes}[^\t]{1,2000}))\t(?:-|({overflow_bytes}[^\t]{1,2000}))\t(?:-|({timedout}[^\t]{1,2000}))\t(?:-|({parent_file_id}[^\t]{1,2000}))\t(?:-|({md5}[^\t]{1,2000}))\t(?:-|({sha1}[^\t]{1,2000}))\t(?:-|({sha256}[^\t]{1,2000}))\t(?:-|({extracted}[^\t]{1,2000}?))\s{0,100}""",
      """\d{10}\.\d{6}\t([^\t]{1,2000}\t){22}(?:-|({extracted_cutoff}[^\t]{1,2000}))\t(?:-|({extracted_size}[^\s]{1,2000}))\s{0,100}$"""
      """\d{10}\.\d{6}\t([^\t]{1,2000}\t){8}(?:-|({file_path}({file_parent}[^\s]{0,2000}?(\\u005c|[\\\/])*)({file_name}[^\s\\\/]{1,2000}?(\.({file_ext}[^\s\\\/\.]{1,2000}))?)))\s{0,100}\\?\t"""
  ]
}
```
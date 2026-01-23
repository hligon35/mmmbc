param(
  [string]$Root = (Resolve-Path (Join-Path $PSScriptRoot ".."))
)

$ErrorActionPreference = "Stop"

$dest = Join-Path $Root "cf_site"

# Ensure the output is an exact mirror of the canonical source files.
# This also removes any stale/duplicate folders (ex: cf_site/Pages/Pages) from prior builds.
if (Test-Path $dest) {
  Remove-Item -Recurse -Force $dest
}
New-Item -ItemType Directory -Force -Path $dest | Out-Null

# Copy top-level public files
$files=@(
  "index.html","robots.txt","sitemap.xml",
  "style.css","theme.css","schedule_app.css","schedule_app.js","script.js",
  "announcements_ticker.js","bulletins_widget.js","facility_rental_form.js","facility_rental_nonmembers_form.js",
  "announcements.json","bulletins.json","documents.json","gallery.json","livestream.json","schedule.json","site-settings.json"
)
foreach($f in $files){
  $src=Join-Path $Root $f
  if(Test-Path $src){ Copy-Item -Force $src (Join-Path $dest $f) }
}

# Copy required directories
$dirs=@("Pages","Icons","ConImg","bulletins","rental")
foreach($d in $dirs){
  $src=Join-Path $Root $d
  if(Test-Path $src){
    Copy-Item -Recurse -Force $src (Join-Path $dest $d)
  }
}

# Copy admin UI (static only) under /admin/
$adminUi = Join-Path $Root "admin\public"
if(Test-Path $adminUi){
  $adminDest = Join-Path $dest "admin"
  New-Item -ItemType Directory -Force -Path $adminDest | Out-Null
  Copy-Item -Recurse -Force (Join-Path $adminUi "*") $adminDest

  # Remove custom login pages from the deployed static admin.
  $remove=@("login.html","login.js","login_legacy.html")
  foreach($f in $remove){
    $p = Join-Path $adminDest $f
    if(Test-Path $p){ Remove-Item -Force $p }
  }
}

# Never publish server code or data
$maybeAdminServer = Join-Path $dest "admin\server.js"
if(Test-Path $maybeAdminServer){ Remove-Item -Force $maybeAdminServer }
$maybeAdminData = Join-Path $dest "admin\data"
if(Test-Path $maybeAdminData){ Remove-Item -Recurse -Force $maybeAdminData }

Write-Host "Built cf_site at: $dest"
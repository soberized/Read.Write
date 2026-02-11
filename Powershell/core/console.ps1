# -- ANSI -------------------------------------------------------------------

$script:esc   = [char]27
$script:pink  = "${esc}[38;5;213m"
$script:reset = "${esc}[0m"

# -- Icons ------------------------------------------------------------------

function Icon([string]$symbol = "!") {
    return "[$pink$symbol$reset]"
}

$script:INFO    = Icon "!"   # [!]
$script:SUCCESS = Icon "+"   # [+]
$script:WARN    = Icon "*"   # [*]
$script:ARROW   = Icon ">"   # [>]
$script:DASH    = Icon "-"   # [-]
$script:DOT     = Icon "."   # [.]
$script:HASH    = Icon "#"   # [#]
$script:AT      = Icon "@"   # [@]
$script:CHECK   = Icon "/"   # [/]
$script:CROSS   = Icon "X"   # [X]

# -- Logging ----------------------------------------------------------------

function Log([string]$msg, [string]$prefix = $INFO) {
    Write-Host " $prefix $msg"
}

function Info([string]$msg) {
    Log $msg $INFO
}

function Success([string]$msg) {
    Log $msg $SUCCESS
}

function Warn([string]$msg) {
    Log $msg $WARN
}

# -- Console ----------------------------------------------------------------

function Enable-Ansi {
    # PowerShell 7+ supports ANSI natively; for Windows Terminal / older hosts
    # we enable virtual terminal processing
    $null = [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
}

function Clear-Screen {
    Clear-Host
}

function Set-Title([string]$text) {
    $Host.UI.RawUI.WindowTitle = $text
}

function Show-Banner([string]$version = "PowerShell", [string]$author = "soberized") {
    Write-Host ""
    Write-Host " read.${pink}write.${reset} | Version ${pink}@${reset} $version"
    Write-Host " Developed by ${pink}${author}${reset}"
    Write-Host ""
}

# -- Import Runs -----------------------------------------------------------
Enable-Ansi

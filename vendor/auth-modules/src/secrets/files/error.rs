use std::fmt;
use std::io;

/// Why a private file was rejected. Messages never include file contents.
#[derive(Debug)]
pub enum PrivateFileError {
    Io(io::Error),
    Symlink,
    NotRegularFile,
    InsecurePermissions { mode: u32 },
    WrongOwner { owner: u32, expected: u32 },
    OwnerUnknown,
    TooLarge { max_bytes: u64 },
    Changed,
    Empty,
    NotUtf8,
    InvalidPath,
}

impl From<io::Error> for PrivateFileError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl fmt::Display for PrivateFileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "secret file I/O error: {error}"),
            Self::Symlink => formatter.write_str("secret file must not be a symlink"),
            Self::NotRegularFile => formatter.write_str("secret file must be a regular file"),
            Self::InsecurePermissions { mode } => write!(
                formatter,
                "secret file mode {mode:04o} grants group/other access; use 0600 or 0400"
            ),
            Self::WrongOwner { owner, expected } => write!(
                formatter,
                "secret file is owned by uid {owner}, expected uid {expected}"
            ),
            Self::OwnerUnknown => formatter
                .write_str("cannot determine the effective uid; configure an explicit owner"),
            Self::TooLarge { max_bytes } => {
                write!(formatter, "secret file exceeds {max_bytes} bytes")
            }
            Self::Changed => formatter.write_str("secret file changed while it was read"),
            Self::Empty => formatter.write_str("secret file is empty"),
            Self::NotUtf8 => formatter.write_str("secret file is not valid UTF-8"),
            Self::InvalidPath => formatter.write_str("secret file path has no file name"),
        }
    }
}

impl std::error::Error for PrivateFileError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

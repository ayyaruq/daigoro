pub const ImageError = error{
    AllocationFailed,
    FileNotFound,
    FileNotRead,
    FileTooSmall,
    InvalidDosHeader,
    InvalidNtHeader,
    InvalidNtHeaderOffset,
    ProtectFailed,
    PatchOutOfBounds,
    RelocationOutOfBounds,
    SectionDataOutOfBounds,
    SectionTableOutOfBounds,
    SectionVirtualOutOfBounds,
    UnknownArch,
    UnknownImageType,
    UnknownRelocationType,
};

pub const ScannerError = error{
    SigNotFound,
    InvalidCapture,
};

pub const OodleError = ImageError || ScannerError || error{
    AllocationFailed,
    AlreadyInitialised,
    DecodeFailed,
    EncodeFailed,
    FileNotFound,
    FileNotRead,
    PatchGuard,
    SigNotFound,
    UnknownArch,
};

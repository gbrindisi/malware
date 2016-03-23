//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ZipLib project. Version 1.0
//	
// module: ziplib.c
// $Revision: 14 $
// $Date: 2014-09-29 20:29:05 +0400 (Пн, 29 сен 2014) $
// description:
//	File and directory compression functions.

#include "ziplib.h"
#include "miniz.h"

PL_ERROR
ZipFileToHandle(PL_WCHAR *Root, PL_WCHAR *Path, PL_WCHAR *FileName, PL_WCHAR *ZipFile)
{
	char *aItemName = PL_NULL;
	PL_WCHAR *ItemName = PL_NULL;
	mz_bool status;
	PL_ERROR err;

	PLPRINTF(("ZIP FILE root=%ws, path=%ws, fname=%ws, ZipFile=%ws\n", Root, Path, FileName, ZipFile));
	
	err = PlWideStrSubCopy(Path, PlWcsLen(Root) + 1, 0, &ItemName);
	if (err) {
		PLPRINTF(("Cant alloc ItemName err=%d\n", err));
		goto cleanup;
	}
	
	PlPathWinToUnixInPlace(ItemName);

	err = PlWideStrToUTF8(ItemName, &aItemName);
	if (err) {
		PLPRINTF(("Cant convert %ws to UTF-8, err=%d\n", ItemName, err));
		goto cleanup;
	}

	PLPRINTF(("ItemName=%ws aItemName=%s\n", ItemName, aItemName));
	status = mz_zip_add_file_to_archive_file_in_place(ZipFile, aItemName, Path, PL_NULL, 0, MZ_BEST_COMPRESSION);
	if (!status)
	{
		PLPRINTF(("ZIP ERROR root=%ws, path=%ws, fname=%ws\n", Root, Path, FileName));
		err = PL_E_MINIZ_ZIP;
	}

cleanup:
	if (ItemName)
		PlFree(ItemName);
	if (aItemName)
		PlFree(aItemName);

	return err;
}

PL_ERROR
ZipDirToHandle(PL_WCHAR *Root, PL_WCHAR *Path, PL_WCHAR *ZipFile)
{
	PL_DIR_ENTRY DirEntry;
	PL_ERROR err;
	PL_DIR_ITER DirIter;
	PL_WCHAR fPath[PL_MAX_PATH];

	if (Path == PL_NULL)
		Path = Root;

	PLPRINTF(("ZipDirToHandle:Path=%ws\n", Path));
	err = PlDirFindFirstFile(Path, &DirEntry, &DirIter);
	if (err) {
		PLPRINTF(("first file path=%ws, error=%d\n", fPath, err));
		goto out;
	}

	do
	{
		PlSnWprintf_s(fPath, PL_MAX_PATH, PL_TRUNCATE, L"%ws\\%ws", Path, DirEntry.FileName);
		if (DirEntry.IsDir)
		{
			char *afDir = PL_NULL;
			PL_WCHAR fDir[PL_MAX_PATH];

			if (DirEntry.FileName[0] == '.')
				continue;

			PLPRINTF(("Found %ws %ws   <DIR>\n", fPath, DirEntry.FileName));
			PlSnWprintf_s(fDir, PL_MAX_PATH, PL_TRUNCATE, L"%ws/", &fPath[PlWcsLen(Root) + 1]);
			PlPathWinToUnixInPlace(fDir);
			err = PlWideStrToUTF8(fDir, &afDir);
			if (!err) {
				mz_bool status = mz_zip_add_mem_to_archive_file_in_place(ZipFile, afDir, PL_NULL, 0, PL_NULL, 0, MZ_BEST_COMPRESSION);
				if (!status)
				{
					PLPRINTF(("ERROR mz_zip_add_mem_to_archive_file_in_place failed! for dir=%ws\n", fDir));
					err = PL_E_MINIZ_ZIP;
				}
				PlFree(afDir);
			}
			ZipDirToHandle(Root, fPath, ZipFile);
		}
		else
		{
			PLPRINTF(("Found %ws %ws\n", fPath, DirEntry.FileName));
			ZipFileToHandle(Root, fPath, DirEntry.FileName, ZipFile);
		}
	} while ((err = PlDirFindNextFile(&DirIter, &DirEntry)) == 0);

	if (err != PL_E_NO_MORE_FILES)
	{
		PLPRINTF(("last file error=%d\n", err));
		goto close_file;
	}

	err = PL_E_OK;

close_file:
	PlDirFindClose(&DirIter);
out:
	return err;
}

PL_ERROR
ZipDir(PL_WCHAR *Dir, PL_WCHAR *ZipFile)
{
	return ZipDirToHandle(Dir, PL_NULL, ZipFile);
}


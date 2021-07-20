//========= Copyright Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
// $Workfile:     $
// $NoKeywords: $
//===========================================================================//

#include "ICommandLine.h"

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

static constexpr int MAX_PARAMETER_LEN = 128;
static constexpr int MAX_PARAMETERS = 256;

class CCommandLine : public ICommandLine {
public:
    CCommandLine(void) {
        m_pszCmdLine = NULL;
        m_nParmCount = 0;
    }

    virtual ~CCommandLine(void) {
        CleanUpParms();
        delete[] m_pszCmdLine;
    }

    void CreateCmdLine(const char* commandline) {
        if (m_pszCmdLine) {
            delete[] m_pszCmdLine;
        }

        char szFull[4096];
        szFull[0] = '\0';

        char* pDst = szFull;
        const char* pSrc = commandline;

        bool bInQuotes = false;
        const char* pInQuotesStart = 0;
        while (*pSrc) {
            // Is this an unslashed quote?
            if (*pSrc == '"') {
                if (pSrc == commandline || (pSrc[-1] != '/' && pSrc[-1] != '\\')) {
                    bInQuotes = !bInQuotes;
                    pInQuotesStart = pSrc + 1;
                }
            }

            if (*pSrc == '@') {
                if (pSrc == commandline || (!bInQuotes && isspace(pSrc[-1])) || (bInQuotes && pSrc == pInQuotesStart)) {
                    LoadParametersFromFile(pSrc, pDst, sizeof(szFull) - (pDst - szFull), bInQuotes);
                    continue;
                }
            }

            // Don't go past the end.
            if ((pDst - szFull) >= (sizeof(szFull) - 1))
                break;

            *pDst++ = *pSrc++;
        }

        *pDst = '\0';

        int len = strlen(szFull) + 1;
        m_pszCmdLine = new char[len];
        memcpy(m_pszCmdLine, szFull, len);

        ParseCommandLine();
    }

    void CreateCmdLine(int argc, char** argv) {
        char cmdline[2048];
        cmdline[0] = 0;

        char* dest = cmdline;
        size_t size = sizeof(cmdline);
        const char* space = "";

        for (int i = 0; i < argc; ++i) {
            if (size) {
                _snprintf(dest, size, "%s\"%s\"", space, argv[i]);
                dest[size - 1] = 0;
            }

            size_t len = strlen(dest);
            size -= len;
            dest += len;
            space = " ";
        }

        CreateCmdLine(cmdline);
    }

    const char* GetCmdLine(void) const {
        return m_pszCmdLine;
    }

    const char* CheckParm(const char* psz, const char** ppszValue = 0) const {
        if (ppszValue)
            *ppszValue = NULL;

        int i = FindParm(psz);
        if (i == 0)
            return NULL;

        if (ppszValue) {
            if ((i + 1) >= m_nParmCount) {
                *ppszValue = NULL;
            }
            else {
                *ppszValue = m_ppParms[i + 1];
            }
        }

        return m_ppParms[i];
    }

    void RemoveParm(const char* pszParm) {
        if (!m_pszCmdLine)
            return;

        // Search for first occurrence of pszParm
        char* p, * found;
        char* pnextparam;
        int n;
        int curlen;

        p = m_pszCmdLine;
        while (*p) {
            curlen = strlen(p);

            found = strstr(p, pszParm);
            if (!found)
                break;

            pnextparam = found + 1;
            bool bHadQuote = false;
            if (found > m_pszCmdLine && found[-1] == '\"')
                bHadQuote = true;

            while (pnextparam && *pnextparam && (*pnextparam != ' ') && (*pnextparam != '\"'))
                pnextparam++;

            if (pnextparam && (static_cast<size_t>(pnextparam - found) > strlen(pszParm))) {
                p = pnextparam;
                continue;
            }

            while (pnextparam && *pnextparam && (*pnextparam != '-') && (*pnextparam != '+'))
                pnextparam++;

            if (bHadQuote) {
                found--;
            }

            if (pnextparam && *pnextparam) {
                // We are either at the end of the string, or at the next param.  Just chop out the current param.
                n = curlen - (pnextparam - p); // # of characters after this param.
                memmove(found, pnextparam, n);

                found[n] = '\0';
            }
            else {
                // Clear out rest of string.
                n = pnextparam - found;
                memset(found, 0, n);
            }
        }

        // Strip and trailing ' ' characters left over.
        while (1) {
            int len = strlen(m_pszCmdLine);
            if (len == 0 || m_pszCmdLine[len - 1] != ' ')
                break;

            m_pszCmdLine[len - 1] = '\0';
        }

        ParseCommandLine();
    }

    void AppendParm(const char* pszParm, const char* pszValues) {
        int nNewLength = 0;
        char* pCmdString;

        nNewLength = strlen(pszParm);            // Parameter.
        if (pszValues)
            nNewLength += strlen(pszValues) + 1;  // Values + leading space character.
        nNewLength++; // Terminal 0;

        if (!m_pszCmdLine) {
            m_pszCmdLine = new char[nNewLength];
            strcpy(m_pszCmdLine, pszParm);
            if (pszValues)
            {
                strcat(m_pszCmdLine, " ");
                strcat(m_pszCmdLine, pszValues);
            }

            ParseCommandLine();
            return;
        }

        // Remove any remnants from the current Cmd Line.
        RemoveParm(pszParm);

        nNewLength += strlen(m_pszCmdLine) + 1 + 1;

        pCmdString = new char[nNewLength];
        memset(pCmdString, 0, nNewLength);

        strcpy(pCmdString, m_pszCmdLine); // Copy old command line.
        strcat(pCmdString, " "); // Put in a space
        strcat(pCmdString, pszParm);
        if (pszValues) {
            strcat(pCmdString, " ");
            strcat(pCmdString, pszValues);
        }

        // Kill off the old one
        delete[] m_pszCmdLine;

        // Point at the new command line.
        m_pszCmdLine = pCmdString;

        ParseCommandLine();
    }

    void SetParm(const char* pszParm, const char* pszValues) {
        int i = FindParm(pszParm);
        if (i == 0)
            return;
        SetParm(i, pszValues);
    }

    void SetParm(const char* pszParm, int iValue) {
        int i = FindParm(pszParm);
        if (i == 0)
            return;
        char buf[16];
        sprintf(buf, "%d", iValue);
        SetParm(i, buf);
    }

private:
    void LoadParametersFromFile(const char*& pSrc, char*& pDst, int maxDestLen, bool bInQuotes) {
        // Suck out the file name
        char szFileName[MAX_PATH];
        char* pOut;
        char* pDestStart = pDst;

        if (maxDestLen < 3)
            return;

        // Skip the @ sign
        pSrc++;

        pOut = szFileName;

        char terminatingChar = ' ';
        if (bInQuotes)
            terminatingChar = '\"';

        while (*pSrc && *pSrc != terminatingChar) {
            *pOut++ = *pSrc++;
            if ((pOut - szFileName) >= (MAX_PATH - 1))
                break;
        }

        *pOut = '\0';

        // Skip the space after the file name
        if (*pSrc)
            pSrc++;

        // Now read in parameters from file
        FILE* fp = fopen(szFileName, "r");
        if (fp) {
            char c;
            c = (char)fgetc(fp);
            while (c != EOF) {
                // Turn return characters into spaces
                if (c == '\n')
                    c = ' ';

                *pDst++ = c;

                // Don't go past the end, and allow for our terminating space character AND a terminating null character.
                if ((pDst - pDestStart) >= (maxDestLen - 2))
                    break;

                // Get the next character, if there are more
                c = (char)fgetc(fp);
            }

            // Add a terminating space character
            *pDst++ = ' ';

            fclose(fp);
        }
        else {
            printf("Parameter file '%s' not found, skipping...", szFileName);
        }
    }

    void ParseCommandLine() {
        CleanUpParms();
        if (!m_pszCmdLine)
            return;

        const char* pChar = m_pszCmdLine;
        while (*pChar && isspace(*pChar)) {
            ++pChar;
        }

        bool bInQuotes = false;
        const char* pFirstLetter = NULL;
        for (; *pChar; ++pChar) {
            if (bInQuotes) {
                if (*pChar != '\"')
                    continue;

                AddArgument(pFirstLetter, pChar);
                pFirstLetter = NULL;
                bInQuotes = false;
                continue;
            }

            // Haven't started a word yet...
            if (!pFirstLetter) {
                if (*pChar == '\"') {
                    bInQuotes = true;
                    pFirstLetter = pChar + 1;
                    continue;
                }

                if (isspace(*pChar))
                    continue;

                pFirstLetter = pChar;
                continue;
            }

            // Here, we're in the middle of a word. Look for the end of it.
            if (isspace(*pChar)) {
                AddArgument(pFirstLetter, pChar);
                pFirstLetter = NULL;
            }
        }

        if (pFirstLetter) {
            AddArgument(pFirstLetter, pChar);
        }
    }

    void CleanUpParms() {
        for (int i = 0; i < m_nParmCount; ++i) {
            delete[] m_ppParms[i];
            m_ppParms[i] = NULL;
        }
        m_nParmCount = 0;
    }

    void AddArgument(const char* pFirst, const char* pLast) {
        if (pLast <= pFirst)
            return;

        if (m_nParmCount >= MAX_PARAMETERS) {
            printf("CCommandLine::AddArgument: exceeded %d parameters", MAX_PARAMETERS);
            return;
        }

        size_t nLen = pLast - pFirst + 1;
        m_ppParms[m_nParmCount] = new char[nLen];
        memcpy(m_ppParms[m_nParmCount], pFirst, nLen - 1);
        m_ppParms[m_nParmCount][nLen - 1] = 0;

        ++m_nParmCount;
    }

    int FindParm(const char* psz) const {
        // Start at 1 so as to not search the exe name
        for (int i = 1; i < m_nParmCount; ++i) {
            if (!_stricmp(psz, m_ppParms[i]))
                return i;
        }
        return 0;
    }

    void SetParm(int nIndex, char const* pParm) {
        if (pParm) {
            if ((nIndex >= 0) && (nIndex < m_nParmCount)) {
                if (m_ppParms[nIndex])
                    delete[] m_ppParms[nIndex];
                m_ppParms[nIndex] = _strdup(pParm);
            }
        }
    }

    char* m_pszCmdLine;
    int m_nParmCount;
    char* m_ppParms[MAX_PARAMETERS];
};

static CCommandLine commandLine;

ICommandLine* CommandLine() {
    return &commandLine;
}

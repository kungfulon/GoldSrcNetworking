//========= Copyright Valve Corporation, All rights reserved. ============//
//
// Purpose: 
//
//===========================================================================//

#ifndef ICOMMANDLINE_H
#define ICOMMANDLINE_H
#ifdef _WIN32
#pragma once
#endif

//-----------------------------------------------------------------------------
// Purpose: Interface to engine command line
//-----------------------------------------------------------------------------
class ICommandLine
{
public:
	virtual void		CreateCmdLine(const char* commandline) = 0;
	virtual void		CreateCmdLine(int argc, char** argv) = 0;
	virtual const char* GetCmdLine(void) const = 0;

	virtual	const char* CheckParm(const char* psz, const char** ppszValue = 0) const = 0;
	virtual void		RemoveParm(const char* pszParm) = 0;
	virtual void		AppendParm(const char* pszParm, const char* pszValues) = 0;

	virtual void		SetParm(const char* pszParm, const char* pszValues) = 0;
	virtual void		SetParm(const char* pszParm, int iValue) = 0;
};

//-----------------------------------------------------------------------------
// Gets a singleton to the commandline interface
//-----------------------------------------------------------------------------
ICommandLine* CommandLine();

#endif // ICOMMANDLINE_H

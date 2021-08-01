#ifndef IENGINELAUNCHERAPI_H
#define IENGINELAUNCHERAPI_H

#ifdef _WIN32
#pragma once
#endif

enum
{
	ENGINE_RESULT_NONE,
	ENGINE_RESULT_RESTART,
	ENGINE_RESULT_UNSUPPORTEDVIDEO
};

class IEngineLauncherAPI : public IBaseInterface
{
public:
	virtual int Run(HINSTANCE instance, char *basedir, const char *cmdline, char *szCommand, CreateInterfaceFn launcherFactory, CreateInterfaceFn filesystemFactory) = 0;
};

#define VENGINE_LAUNCHER_API_VERSION "VENGINE_LAUNCHER_API_VERSION002"

#endif // IENGINELAUNCHERAPI_H

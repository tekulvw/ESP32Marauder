#pragma once
#include <Arduino.h>
namespace passive_evidence {
bool active();
bool command(const String& input);
void tick();
}

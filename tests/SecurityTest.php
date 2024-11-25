<?php

namespace DomainChecker\Tests;

use DomainChecker\Security;
use PHPUnit\Framework\TestCase;

class SecurityTest extends TestCase
{
    public function testValidDomainPasses()
    {
        $this->assertTrue(Security::isValidDomain('example.com'));
        $this->assertTrue(Security::isValidDomain('sub.example.com'));
        $this->assertTrue(Security::isValidDomain('example-domain.com'));
    }
    
    public function testInvalidDomainFails()
    {
        $this->assertFalse(Security::isValidDomain(''));
        $this->assertFalse(Security::isValidDomain('.com'));
        $this->assertFalse(Security::isValidDomain('example..com'));
        $this->assertFalse(Security::isValidDomain('example.com.'));
        $this->assertFalse(Security::isValidDomain('exa mple.com'));
        $this->assertFalse(Security::isValidDomain('ex@mple.com'));
    }
    
    public function testCleanDomainNormalizes()
    {
        $this->assertEquals('example.com', Security::cleanDomain('EXAMPLE.COM'));
        $this->assertEquals('example.com', Security::cleanDomain('example.com.'));
        $this->assertEquals('example.com', Security::cleanDomain(' example.com '));
    }
    
    public function testCleanDomainThrowsOnInvalid()
    {
        $this->expectException(\InvalidArgumentException::class);
        Security::cleanDomain('invalid@domain');
    }
    
    public function testSafeExecuteWithValidCommand()
    {
        $result = Security::safeExecute('dig', ['+short', 'NS', 'google.com']);
        $this->assertIsArray($result);
        $this->assertArrayHasKey('output', $result);
        $this->assertArrayHasKey('error', $result);
        $this->assertNotEmpty($result['output']);
    }
    
    public function testSafeExecuteWithInvalidCommand()
    {
        $this->expectException(\RuntimeException::class);
        Security::safeExecute('invalid_command', ['arg1']);
    }
    
    public function testSafeExecuteWithTimeout()
    {
        $this->expectException(\RuntimeException::class);
        Security::safeExecute('dig', ['+trace', 'google.com'], 1); // 1 second timeout
    }
}

/*************************************************************************
 *
 * Copyright (C) 2018-2024 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "dns_rules.h"
#include "gtest/gtest.h"

#include <map>

class DomainRules : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(DomainRules, order)
{
	struct dns_domain_rule _domain_rule;
	struct dns_domain_rule *domain_rule = &_domain_rule;
	domain_rule_init(domain_rule);
	ASSERT_NE(domain_rule, nullptr);

	std::map<int, struct dns_rule *> rules;
	domain_rule_set_flag(domain_rule, DOMAIN_FLAG_ADDR_SOA);
	for (int i = 0; i < DOMAIN_RULE_MAX; ++i) {
		struct dns_rule *rule = (struct dns_rule *)_new_dns_rule((enum domain_rule)i);
		EXPECT_NE(rule, nullptr);
		rules[i] = rule;
		EXPECT_EQ(domain_rule_set(domain_rule, (enum domain_rule)i, rule), 0);
	}

	unsigned int flags;
	EXPECT_EQ(domain_rule_get_flags(domain_rule, &flags), 0);
	EXPECT_EQ(flags, DOMAIN_FLAG_ADDR_SOA);
	for (int i = 1; i < DOMAIN_RULE_MAX; ++i) {
		EXPECT_EQ(domain_rule_get(domain_rule, (enum domain_rule)i), rules[i]);
	}

	domain_rule_set_flag(domain_rule, DOMAIN_FLAG_DUALSTACK_SELECT);
	EXPECT_EQ(domain_rule_get_flags(domain_rule, &flags), 0);
	EXPECT_EQ(flags, DOMAIN_FLAG_ADDR_SOA | DOMAIN_FLAG_DUALSTACK_SELECT);
	domain_rule_set_flag(domain_rule, DOMAIN_FLAG_NO_DUALSTACK_SELECT);
	EXPECT_EQ(domain_rule_get_flags(domain_rule, &flags), 0);
	EXPECT_EQ(flags, DOMAIN_FLAG_ADDR_SOA | DOMAIN_FLAG_NO_DUALSTACK_SELECT);
	EXPECT_EQ(domain_rule_free(domain_rule), 0);
}

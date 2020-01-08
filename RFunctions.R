library(readr)
library(dplyr)
library(tidyr)
library(ggplot2)
library(RColorBrewer)
warnings()

csv <- read_csv("DL_vulnerabilities_abtes2mv_20191217.csv", skip = 3)
cols <- ncol(csv)
rows <- nrow(csv)

print(cols)
print(rows)

# Select necessary fieds
my_df <- select(csv,QID,matches("CVE ID"),Category,matches("Sub Category"),matches("CVSS Base"),matches("CVSS3 Base"))

# Filter dataframe to remove incomplete rows
df <- filter(my_df, !is.na(my_df$`CVE ID`))
df <- filter(df, df$`CVSS Base` != '\'-')
df <- filter(df, df$`CVSS3 Base` != '\'-')

# Split dataframe by CVE ID column, adding a new row with the same info
df_elegant <- strsplit(df$`CVE ID`, split = ",")
elegant_data <- data.frame(QID = rep(df$QID, sapply(df_elegant, length)), `CVE ID`  = unlist(df_elegant), Category = rep(df$Category, sapply(df_elegant, length)), `Sub Category` = rep(df$`Sub Category`, sapply(df_elegant, length)), `CVSS Base`  = rep(df$`CVSS Base`, sapply(df_elegant, length)), `CVSS3 Base`  = rep(df$`CVSS3 Base`, sapply(df_elegant, length)))

# Order the dataframe by Category
order_by_category <- arrange(elegant_data, elegant_data$Category)

# Change to type numeric CVSS.Base and CVSS3.Base columns
order_by_category$CVSS.Base <- as.numeric(as.character(order_by_category$CVSS.Base))
order_by_category$CVSS3.Base <- as.numeric(as.character(order_by_category$CVSS3.Base))

# Based on CVSS standard, filter the dataframe to keep only the vulnerabilities with a high impact
critic_cves <- filter(order_by_category, order_by_category$CVSS.Base >= 7.0)




# Modifies the dataframe "order_by_category" to obtain a dataframe containing the categories of vulnerabilities
# and the number of vulnerabilities grouped by its impact based on "CVSS.Base column
cvss_impact_df <- order_by_category %>% group_by(Category) %>% summarise(high = sum(CVSS.Base >= 7.0),
                                                       medium = sum((CVSS.Base > 3.9) & (CVSS.Base < 7.0)),
                                                       low = sum((CVSS.Base <= 3.9))
                                                       )

# Extracts observations from "cvss impact" variables
cvss_impact_df <- gather(cvss_impact_df,"CVSS_Impact","num_cves",2:4)

# Order the dataframe by category
cvss_impact_order_df <- arrange(cvss_impact_df, cvss_impact_df$Category)

#display.brewer.all()
#display.brewer.pal(n = 2-3, name = 'Accent')

# Set the colors to be used in the next plot
my_colors <- list("#FFC0CB","#F0E68C","#AFEEEE")

# Creates a plot that represents the number of vulnerabilities by category that belongs to 
# CVSS high impact, medium impact or low impact 
ggplot(data=cvss_impact_order_df, aes(x=cvss_impact_order_df$Category, y=cvss_impact_order_df$num_cves, fill=cvss_impact_order_df$CVSS_Impact)) + 
  geom_bar(stat="identity") +
  scale_fill_manual(values = my_colors) +
  labs(title="Vulnerabilities by Impact", fill="CVSS Impact") + 
  xlab("Categories") + 
  ylab("Nº Vulnerabilities")




# Create the plot
plot(x = critic_cves$Category,main="Vulnerabilities with HIGH impact",xlab = "Categories", ylab = "Nº Vulnerabilities")
#plot(x = critic_cves$Category, horiz = TRUE, las = 1)
a <- ggplot(order_by_category, aes(x=Category, y=CVSS.Base, fill = CVE.ID))
a + geom_bar() + labs(title="Vulnerabilities with HIGH impact") + xlab("Categories") + ylab("Nº Vulnerabilities")


#g <- ggplot(order_by_category, aes(CVSS.Base, CVSS3.Base, color = Category))
#g + geom_count() + labs(title="CVSS vs CVSS3") + xlab("CVSS") + ylab("CVSS3")



#info <- critic_cves %>% group_by(Category) %>% summarise(cve_num = n(),
#                                                          cvss_mean = mean(CVSS.Base),
#                                                          cvss3_mean = mean(CVSS3.Base)
#)
#plot(x = info$Category,y = info$cve_num)

#elegant_data$CVSS.Base <- as.numeric(as.character(elegant_data$CVSS.Base))
#elegant_data$CVSS3.Base <- as.numeric(as.character(elegant_data$CVSS3.Base))
#
#info <- elegant_data %>% group_by(Category) %>% summarise(cve_num = n(),
#                                                                       cvss_mean = mean(CVSS.Base),
#                                                                       cvss3_mean = mean(CVSS3.Base)
#                                                                       )
#
#critic_cve <- filter(info, info$cvss_mean >= 7.0)



#cves_cpes <- select(cves.sample,cve.id,vulnerable.configuration)